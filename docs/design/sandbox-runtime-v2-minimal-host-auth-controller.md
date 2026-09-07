# Selected host authenticated controller: bounded implementation slice

Design only, inspected at `99b58782390f0805efbdaf01d4eadbb52f70bb79`.
The accepted [controller design](sandbox-runtime-v2-minimal-host-controller.md),
[Linux architecture](sandbox-runtime-v2-linux-completion-architecture.md) and
[L8 reset](sandbox-runtime-v2-l8-credential-runtime-contract-reset.md) govern.
This note proposes the next transcript/lifetime consumer, not another protocol,
runtime owner, readiness issuer or completed production route. The original
design checkpoint was `0549144d`; its approved compiling RED adds only unavailable
wrapper/types and dedicated fixture tests, not a working controller.

## Available concrete dependencies

Paths below are relative to `internal/sandboxruntime/microvm/`.

| Existing seam | What the new consumer can reuse |
| --- | --- |
| `firecrackerhost/minimal_control_startup.go`, `OpenWhenAvailable` | One claimed connector, original retained manager/process/UID/parent authority, bounded pre-ACK retries, one transport generation and effective absolute admission deadline |
| `firecrackerhost/minimal_control_transport.go`, `minimalControlStream` | Actual Unix connection, owner/process/socket watcher, `Correlation`, hard deadline, deadline-aware I/O, close plus watcher join |
| `firecrackerhost/minimal_control_config_linux.go`, `withMinimalControlSupervisorAdmission` | Selected sealed byte admission; seed FD already consumed; callback-scoped signing-key allocation cleared when the callback returns |
| `firecrackerhost/minimal_control_config.go`, `minimalControlSupervisorAdmission` | Validated public config, complete config digest and borrowed key; explicitly not runtime/store/readiness authority |
| `guestagent/minimalcontrol` | `NewBinding`, `BootstrapPrelude`, `EncodeReadinessRequest`, `ValidateReadinessResponse`; immutable copied binding and existing canonical 25/27-field rules |
| `guestagent/session` | Existing exact-identity Ed25519/X25519 handshake, Finished ordering, encrypted records/counters, five-second handshake and hard expiry |

The accepted design's earlier statements that startup retry/shared host codec are
absent are historical at its recorded base: both APIs exist here. Their behavior
must be consumed, not duplicated. The selected executable still calls
`unavailableMinimalControlSupervisor`; this slice does not change that gate.

## Smallest input and lifetime boundary

Proposed private API, entirely within `firecrackerhost`:

```text
withMinimalControlController(ownerCtx, transport, admission, D, consume) -> error
    transport: *minimalControlTransport, original concrete retained connector
    admission: *minimalControlSupervisorAdmission, borrowed inside its callback
    consume: func(*minimalControlController) error, a scoped owner-loop consumer

controller.WaitReady(waitCtx) -> *minimalControlReadiness, error
controller.Loss() -> closed-channel notification
controller.Close() -> error                 // cancel, close I/O, join; idempotent
readiness.Current() -> bool                 // transient local session correlation
```

There is no `io.ReadWriteCloser`, PID/path constructor, interface-supplied readiness
proof or caller-provided `Current` callback at this boundary. The existing concrete
transport resolves the original manager record and enforces strict owner/socket/
peer identity. Tests reuse its existing private ownership observations; those
observations never become a production constructor option.

The wrapper rejects absent/invalid context, connector, admission, key, deadline
or consumer before starting the transcript. It snapshots the public prelaunch map
and scalar pins before starting a goroutine; caller mutation is not adopted.
Reusing `RenderBootCommandLine` with an empty base validates partial public pins
without a second schema or late-generation placeholders. That validation is not
new FC config rendering, descriptor issuance, L7 enforcement or launch authority.
The key's size/public-key correlation and the transport's runtime must match the
admitted pins. No recovery root key is accepted as entropy or signing material.

`D` is mandatory input from the later selected gate-send barrier:
`min(original preparation deadline, conservative pre-release timestamp + 15s)`.
Reject zero/expired D and D beyond the admitted preparation deadline. This consumer
cannot prove a caller sampled the timestamp at the real gate send; the later
runtime integration must provide that exact source. It must not calculate D from
controller construction, successful Open, bootstrap reply or readiness time.

The wrapper borrows the admitted signing-key slice; it does not retain the seed FD
or make a second long-lived key copy. The outer admission callback remains active
for the entire nested controller scope. On callback return/panic, the wrapper first
closes and joins its controller, then returns to the loader's existing deferred
wipe. Thus loader cleanup cannot race an escaped transcript using that allocation.
Every wrapper rejection clears the borrowed key too. The transcript clears it
earlier as described below; callback completion is only the final safety net.

One controller is constructed for one claimed connector. Concurrent WaitReady
calls share the same result/loss latch; canceled waiters do not cancel an accepted
owner. Callback return, explicit Close or ownerCtx loss does cancel the controller.
The caller must not supply the initiating CLI's context or an admission-only
context that is canceled at readiness. No retry uses a second connector or key.

The private readiness handle retains its controller pointer and immutable binding,
session ID, exact process handle and transport generation. It is unmarshalable and
not independently constructible from a returned value struct. Currentness checks
its latch, original stream correlation, context and earliest hard expiry. It is
not a `JobCredentialIdentitySeed`, v1 readiness record, credential grant, original-
channel ready event or terminal cleanup receipt.

## Transcript and exact budgets

1. Call the existing `OpenWhenAvailable(ownerCtx, D)` exactly once. It may shorten
   D; retain the returned `stream.admissionDeadline` and never extend it. No second
   local retry loop, v1 probe or fixed readiness prelude is used.
2. Read `stream.Correlation`, require the original transport handle/source and
   nonzero counter, and fill only the two late fields. Process generation is the
   actual handle ID; vsock generation is the canonical decimal counter. Construct
   `session.Identity` and `minimalcontrol.NewBinding` from the copied public pins.
3. Immediately before the bootstrap prelude, set one absolute
   `A = min(original D, effective stream D, now + session.HandshakeDeadline)`.
   Set the stream deadline to A and use A for the rest of admission. Check the
   half-open bound after each potentially delayed observation and immediately
   before local readiness publication, independently of timer callback delivery.
4. Send the shared `Binding.BootstrapPrelude` through bounded frame encoding.
   Read one four-byte-length GuestHello, at most 4096 inner bytes. Construct the
   unchanged `session.NewControllerHandshake` using the exact completed identity
   and borrowed key. Immediately install its existing consume-on-error cleanup
   (`AcceptGuestHello(nil)`), clear the original key after constructor copying,
   then accept the actual Hello. A constructor failure clears the original too.
   The session's own deadline can shorten A but cannot reset it.
5. Send ControllerAuth; receive and verify guest Finished; send controller
   Finished; require established state. Use the existing session order/counters.
6. Draw one canonical 16-byte request ID and use the shared readiness encoder.
   `State.WriteApplication` sends `FrameTypeControlRequest`. Read exactly one
   secure response and call `State.OpenApplication` with a validator requiring
   `FrameTypeControlResponse` and the shared exact request/session/binding
   response validator. No parallel response struct/capability list is introduced.
7. Transfer the sole reader role from the transcript to one owned idle reader;
   wait for its armed notification, then recheck A and exact stream correlation
   before publishing local readiness once. Replace A only with the earliest
   owner/transport/session hard expiry H, never an unlimited deadline or a new
   lifetime. The idle reader performs one bounded one-byte read: any byte, EOF
   or error retires readiness. There is no competing transcript reader or drain
   task. A concurrently observed loss wins the local publication latch; no claim
   is made that physical peer loss is known before its I/O observation.

The controller uses the stream's socket deadlines for blocking admission/idle I/O,
and its existing owner watcher interrupts cancellation. There is no extra
admission timer that survives readiness or silently renews the budget. The host
session hard expiry may differ from the guest's earlier handshake start; H is
conservatively clamped to the existing transport hard limit, and guest EOF remains
terminal. Key generation for producer boot inputs remains a separate owner task.

The selected host random reader is concrete and bounded: one Linux nonblocking
`getrandom` call for each 32-byte request, fail on short/error, wipe scratch, no
fallback. Supply it through the unchanged `session.Dependencies.Random` slot.
The readiness request uses one such draw, takes 16 bytes for lowercase hex, then
wipes the whole draw. No arbitrary blocking entropy reader is accepted by the
production wrapper; private deterministic observations belong only to tests.

New read helpers own their buffers. Read a fixed handshake/header prefix first,
validate its length before allocating, and clear every partial allocation on
error. Secure records are capped at 52 + 8192 + 16 bytes, not the broader generic
control maximum. Clear Hello/Auth/Finished/request/response/plaintext and encrypted
record buffers on success and failure. Existing framing helpers that lose access
to a partial buffer are not sufficient evidence of wiping. No new claim is made
about physically wiping crypto-library internal allocations.

## Close and join order

Use one private lifecycle latch, one transcript/lifetime task and, after reader
handoff, one joined idle reader; no new daemon/cleanup owner. No controller mutex
is held across I/O, manager observations or joins.

1. Atomically retire readiness/loss, cancel the controller's owned child context,
   and close the current guest stream outside the controller mutex. If Open has
   not returned, cancellation makes that existing connector finish/join its own
   attempt. A returned stream is either installed in the live controller or
   immediately closed when cancellation already won.
2. Stream Close interrupts I/O and joins the existing transport watcher. Join the
   controller task, which itself joins any armed idle reader before finishing.
   The idle reader only retires the latch/cancels and returns; it never calls a
   joining Close or containment, so it cannot wait for itself.
3. Only after its last write/read has returned does the protocol task call
   `State.Revoke`, clear remaining buffers/key and finish. In particular external
   Close never calls Revoke while `WriteApplication` may hold `State.mu` across a
   blocked write. Close returns only after revocation/wiping has completed.

That describes local controller cleanup, not VM absence. The later existing
supervisor must perform this close/join barrier before entering authenticated
`HandleController` cleanup or any selected containment/owner mutex. The controller
never calls containment from a reader or invents a callback that asserts it ran.
On stream loss, the future selected lifecycle consumer receives Loss and invokes
the same existing cleanup owner after the barrier.

## Staged compiling RED and ownership

The approved first RED adds only the minimum unavailable private wrapper/type
declarations needed to compile the real transcript test. It fails at the missing
consumer, not at socket setup or a deliberately wrong key. An independent
test-only reference transcript completes the actual retained Unix transport and
shared guest bootstrap. The fixture listener closes only pending acceptance at
readiness, retaining the active guest stream and pinned socket until owned cleanup.
Later assertions inside the unavailable consumer remain unexecuted until GREEN.

```sh
go test -p 2 -race -count=3 ./internal/sandboxruntime/microvm/firecrackerhost -run '^TestMinimalControlController'
```

At the first RED this selects one missing-consumer failure per repetition, while
the real fixture control and seven early-rejection/key-wipe cases pass. The early
controls pass because the boundary is wholly unavailable; they are not evidence
of a completed admission validator or the later deadline/lifetime fault matrix.

Prospective owned files:

- `firecrackerhost/minimal_control_controller_linux.go`: scope/lifetime and
  concrete transport admission; no selected runtime constructor or store edits.
- `firecrackerhost/minimal_control_controller_wire_linux.go`: bounded transcript,
  scalar pin projection and clearing helpers; shared codecs/crypto unchanged.
- `firecrackerhost/minimal_control_controller_entropy_linux.go`: concrete bounded
  host entropy, with a narrow syscall test seam, not an exported reader option.
- `firecrackerhost/minimal_control_controller_*_test.go`: adjacent default Linux
  tests, with no CLI/VM/KVM/privilege dependency.

First positive test combines the existing production-bridge/strict-owner fixture
components, original manager/handle, ordinary private Unix socket, real CONNECT/ACK and
`minimalcontrol.NewBootstrap` server plus unchanged session cryptography. It
requires one completed transcript, an exact session-bound readiness digest,
one transport generation, no legacy bridge session, key clearing and joined Close.
The process record is fake, while peer/parent observations use the actual
nonzero caller UID; this does not prove dedicated UID ownership or live Jailer.

Follow-on reachable REDs cover:

- missing/stale/closed transport, wrong runtime/pins/key, original D expiry and
  preclaimed connector: no guest readiness and no replacement/fallback;
- wrong Hello identity, malformed/partial/oversized handshake and secure frames,
  wrong request/binding/session/capability response and unsolicited postready byte;
- exact D/A expiry despite delayed observation/timer, no A rebasing after Hello
  or readiness, and earliest hard expiry after successful admission;
- cancellation/owner/process/socket loss at Open, prelude, Hello, Finished,
  readiness write/read and idle; original stream closed and every task joined;
- blocked `WriteApplication` plus concurrent Close: I/O closes before Revoke,
  completion without watchdog rescue, no self-join or duplicate publication;
- concurrent waiters, canceled waiter versus explicit owner cancellation,
  callback return/panic, and all key/partial-buffer cleanup paths.

Use actual transport integration as the primary positive. Narrow per-instance
clock/I/O fault observations can exercise precise boundaries after it is working;
they must not substitute for an accepted concrete owner or bypass its currentness.
Focused/race tests and adjacent package/source guards, vet and Darwin compile
follow GREEN. Runtime wiring remains separately assigned.

## Initial controller GREEN checkpoint

The dedicated controller now executes the real shared transcript from the
retained transport, completes the exact two late generations, clears the
borrowed signing key after the shared handshake takes its scoped copy, and
publishes only a transient local readiness handle. A single armed idle reader
retires that handle on any byte, EOF or error. `Close` first retires/cancels and
closes stream I/O outside its mutex, then joins the transcript/idle task and
transport watcher before the task revokes its private session state. Returning
from the callback always joins that scope; the wrapper's successful return is
historical local transcript completion, not current runtime readiness.

The original RED file is unchanged. Its real Unix transport/guest-bootstrap
positive, exact readiness binding, one CONNECT, early invalid-scope/key clearing,
no legacy readiness and joined Close assertions now execute and pass. This
initial checkpoint does not establish the later fault matrix listed above.
In particular delayed deadline observations, partial reads/writes, entropy
failure, callback panic, idle loss and concurrent shutdown need independently
reachable regression coverage before controller acceptance. No selected runtime
constructor, config/store/admission, producer, shared protocol or cryptography
was changed; the production supervisor still has no controller consumer.

The first follow-on tests-only checkpoint passes without a production change;
these are regression controls, not newly reproduced defects. Alias-observing
readers check partial prefix/body clearing on errors and panics, exact allocation
caps, and single-attempt short-write rejection. Entropy wrong-extent rejection
clears supplied scratch without a syscall test seam. Actual retained Unix/shared
bootstrap tests check owner versus waiter cancellation, callback return/panic
before and after readiness, concurrent Close/WaitReady, guest EOF, fake recorded
process exit, ordinary socket/parent replacement, and stale/key rejection.
Preparation cancellation uses the transport's existing private dial observation
before a real Unix dial; replacement tests preserve successor paths. No new
production dependency or clock/I/O seam was added. Unsolicited-byte and malformed
transcript integration, blocked authenticated writes, delayed absolute A/D/H and
entropy syscall failures remain separate fault-test work.

The second tests-only checkpoint also passes unchanged production. Its guest-side
wrapper uses the real shared bootstrap and crypto, after explicitly joining the
original unconnected fixture and preserving the unused transport, original
manager/process identity, retained parent and displaced socket. A positive
transcript control precedes length/magic/truncation/Hello-identity/ciphertext
corruption, owner cancellation at three guest writes, and an unsolicited byte
emitted only after host readiness. Oversized declarations keep the peer open to
require rejection before body read or admission expiry. These tests do not
replace authenticated semantic readiness mutations or prove blocked host
`WriteApplication`, delayed A/D/H observation, or entropy syscall failure handling.

The third tests-only checkpoint uses a scripted peer on that same retained Unix
fixture with real shared Hello/Auth/Finished and application cryptography. It
validates the actual request against the shared encoder and first validates an
unmodified response against the shared response validator. The matching response
passes; authenticated wrong binding, capability, session, request, operation,
protocol, OK value, missing/unknown fields and a validly encrypted event kind are
rejected before admission expiry. These are semantic regression controls, not
raw ciphertext corruption, production guest behavior or a new runtime consumer.

The entropy regression checkpoint extracts only the existing single-draw
algorithm into a private helper; the concrete reader passes `unix.Getrandom`
directly, not a configured or global dependency. Exact 32-byte extent,
`GRND_NONBLOCK`, one call, zero/short/invalid counts, EINTR/EAGAIN, full count with
error, and panic-after-fill are checked through aliases of the actual scratch.
Failures wipe before returning the sanitized error; panic propagation is unchanged
and also wipes. These are already-green algorithm regressions, not evidence of
an existing entropy defect or successful host random-source provisioning.

The blocked authenticated-write regression uses the same retained Unix transport
and a scripted real-crypto peer that stops reading only after validating
Finished. Its test-only observation fills the actual socket send buffer with
bounded uninterpreted filler, restores the original D, and confirms the host
task is blocked in `State.WriteApplication` and the real kernel-backed write,
not in the filler callback. Explicit Close and owner cancellation both join and
wipe before D. This exercises close-I/O-before-join/Revoke ordering without a
new production I/O dependency; it is an already-green shutdown regression.

Absolute-bound regressions use the existing per-instance owner observation and
real time, not a production clock seam. They delay prelude/final-publication
checks past original D, and delay the final check past prelude+5s while original
D remains open and a matching authenticated response has completed. No transient
ready event may be published. Ready sessions independently expire at retained
transport/owner H without extending it at authentication. In-transcript panic
tests select the actual application write with shared State held, and the final
publication observation; both sanitize failure, close/join and wipe without
readiness. Together with the earlier callback and partial-buffer panic controls,
these pass existing behavior; they are not newly reproduced defects.

## Explicit next coupled handoff

Composition owns the distinct config/record/store foundation. The selected runtime
constructor is a separately assigned later dependency. This slice must not edit
those files or change the unavailable
production dispatch. Later wiring must supply the actual manager/process only
after the gated release, retain this scope while cleanup reconnect is served,
and recheck the same coordinator generation plus original owner channel before
publishing the one selected ready event. Local readiness does not perform those
two checks by accepting a generic true-returning callback.

Original-channel monitoring/notification, selected startup cancellation and the
pre-release D timestamp, authenticated cleanup dispatch before owner.mu, producer
reservation adoption and L7 loss/terminal correlation remain required integration
work. The L7 session/proxy stay in the original producer; J/controller closure
does not prove network cleanup. No credential operations, reconstructed restart
readiness, all-owner-loss recovery, strict default or live VM acceptance is added.
