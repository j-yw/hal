# Selected minimal bootstrap: implementation and verification boundary

## Scope and status

Base: `0a41be54479fe0baf86b45154b650966fe0d96f4`, including the accepted
[injected minimal control](sandbox-runtime-v2-minimal-authenticated-control-design.md).
The [Linux architecture](sandbox-runtime-v2-linux-completion-architecture.md)
and [L8 reset](sandbox-runtime-v2-l8-credential-runtime-contract-reset.md) remain
authoritative. The design and executable routing RED were frozen in
`a39981ea41cad9da135ac8d46f54a1ea90671fbd`; the subsequent GREEN implements
the bounded guest bootstrap and explicit entrypoint selection described here.

`run()` now delegates through a private dependency seam; the legacy listener,
backend, verifier, server and cleanup body is otherwise unchanged. The helper
called that legacy constructor unconditionally at RED. The original test supplies
public boot strings and counted constructors to this actual helper: selected
and malformed minimal settings reach legacy construction without reading boot
input at RED. That is the observed RED, not an absent-symbol or parser-shape test.
Those assertions are unchanged and now pass through the production parser and
actual routing helper. The selected adapter constructs `NewBootstrap`, not a
v1 transport/backend; injected malformed streams also exercise that adapter.
No test opens a socket, reads real boot state, or calls a workload backend.

GREEN implements only public boot parsing/loading, provisional identity
completion inside the existing acceptor, nonblocking entropy, the fixed control
listener dispatch, and actual agent profile selection. No credentials, workload
dispatch, host launch,
network enforcement, PID1 mutation, image build, or readiness-proof consumer
is implemented here. Public metadata is not runtime authority by itself.

## Immutable boot envelope and producer API

The sole guest source is `/proc/cmdline`, read once with the existing L7 loader's
bounded/no-follow/regular-file/context-check pattern, with at most 4097 bytes
read and a 4096-byte **whole command-line** limit. No CLI option, environment,
workspace file, candidate receipt or fallback source may replace it. Read
errors, NUL and overflow fail before any listener/backend constructor. One
terminal newline is accepted and counted; embedded/repeated newlines and other
ASCII controls except tab are rejected. Missing minimal keys on an otherwise
usable command line preserve legacy selection.

Ten exact keys are required together:

| Key (`hal_minimal_` prefix) | Value |
| --- | --- |
| `profile` | `guest-agent-minimal-v1` |
| `controller_key` | canonical unpadded raw-URL base64 of 32 public key bytes; reject the all-zero value |
| `controller_key_generation` | safe ID, 1–64 ASCII bytes |
| `boot_nonce` | canonical unpadded raw-URL base64 of 32 nonzero nonce bytes |
| `runtime_id`, `runtime_generation` | safe IDs, 1–64 bytes each |
| `boot_generation`, `image_generation` | safe IDs, 1–64 bytes each |
| `image_sha256` | nonzero 64 lowercase hexadecimal digits |
| `prelaunch_binding_sha256` | nonzero 64 lowercase hexadecimal digits |

The reserved namespace includes bare `hal_minimal` and `hal_minimal_*` keys.
For namespace detection only, remove leading/trailing single/double quotes
from the key and compare its prefix case-insensitively; any such spelling
change is rejected, not normalized into acceptance or treated as absence.
Reject missing/partial, unknown, duplicate (even identical), empty,
malformed, noncanonical or wrong-profile settings. Keys from other namespaces,
including `hal_l7_*`, retain their own parser semantics. Values never use shell
quoting or escaping. No ID is truncated, hashed as a substitute, or remapped.

At the maximum 64-byte ID lengths this complete minimal suffix occupies 846
ASCII bytes including its nine internal spaces, excluding the separator/base
arguments. The producer must check the actual final combined length, including
existing kernel and L7 arguments; individual parsers do not get separate 4-KiB
budgets. The renderer reserves one byte for the newline that Linux appends to
`/proc/cmdline`: at most 4095 rendered bytes, then at most 4096 guest-visible
bytes. It rejects a newline in its base argument instead of normalizing it.
Oversize fails before launch. The rootfs image digest and rendered boot
configuration digest remain separate; neither recursively includes the other.

Exported helpers in `guestagent/minimalcontrol`:

```go
type BootConfig struct { /* immutable, opaque public pins; JSON {} */ }

func ParseBootCommandLine(string) (BootConfig, bool, error)
func ReadLinuxBootCommandLine(context.Context) (string, error)
func RenderBootCommandLine(base string, prelaunchIdentity session.Identity,
    controllerPublicKey ed25519.PublicKey,
    prelaunchFields map[string]string) (string, error)
func (Binding) BootstrapPrelude() ([]byte, error)
```

The renderer requires the control channel/CID3/port1025, validated nonzero
nonce/image and public key, no relay/job/activation identity fields, and
**empty** process/vsock generations. Its map has exactly the accepted binding's
25 fields excluding `processGeneration` and `vsockGeneration`. Validate every
field with the same canonical bounds and correlate runtime/boot/image fields
to the supplied partial identity. A private common field validator can handle
25 versus 27 required keys; do not invent placeholder late generations merely
to call `NewBinding` or weaken `session.Identity` validation.

Compute the prelaunch digest exactly as the accepted design specifies:
NUL-terminated domain `hal/guest-agent-minimal-v1/prelaunch-binding/v1`, uint16
big-endian count 25, then sorted ASCII keys with uint16 key/value lengths and
raw bytes. There is **no session ID** at this stage. The rendering helper derives
that digest from the validated map rather than accepting a caller digest label
as proof. Freeze/copy the input maps and key slices. The host producer must
obtain all 25 fields from its current job/admission/L7/runtime owners; this
pure helper does not establish their liveness or trust.

## Late prelude and shared acceptor lifetime

Once the same host supervisor retains the actual strict Jailer process and
socket after gate release, it obtains real process/vsock generations. This is
not a serialized daemon PID, socket-existence inference or prior v1 readiness.
The host constructs the full `session.Identity` and `NewBinding(identity,
full27Fields)`, then sends `binding.BootstrapPrelude()` on that retained stream.

The initial frame uses the existing four-byte length prefix, maximum
8192 bytes, and exactly this compact canonical JSON shape:

```json
{"binding":{},"operation":"bootstrap","protocolVersion":"guest-agent-minimal-v1"}
```

The illustrated empty map is invalid. It contains all 27 fields, with the same
exact unescaped keys, sorted objects, canonical ASCII strings, depth and byte
bounds as the accepted readiness codec. The only newly supplied identity facts
are the two actual late generations. Recompute the 25-field prelaunch digest
and compare it to immutable boot pins; independently correlate the runtime,
boot and image fields. Build the full identity using the pinned nonce/key
generation, fixed control channel/CID/port and those two late generations.

The independent golden vector in `TestBootstrapPrelaunchGoldenAndImmutableInputs`
uses the 25 explicit fixture values, 853 encoded bytes, and SHA-256
`380806f309fa7e04e6061d84f2e864ebb332706dcb7becba035b65d3e875cca8`.
It was calculated separately using Python `hashlib` and `struct.pack('>H')`,
not the production encoder or a paired decoder.

These provisional bytes remain unauthenticated. Only after validation may the
guest emit GuestHello. The existing ControllerAuth signature covers the full
GuestHello/transcript; unchanged Finished messages establish the session.
Finally the existing encrypted readiness request must match the complete
27-field binding and session-bound digest. No provisional parse, digest match,
GuestHello, socket or unsigned acknowledgment is authenticated readiness.

The distinct `NewBootstrap(BootstrapOptions)` uses `BootConfig`, injected
listener, owner-loss channel, clock and entropy. Reuse the existing `Server`
lifecycle, not a new server for each provisional connection. Parsing the late
prelude must occur **inside** its existing 15-second boot budget, five-second
attempt deadline, three-total-attempt gate and owned-stream cleanup. Malformed,
truncated, mismatched or unauthenticated provisional input consumes an attempt;
it never resets the budget. The third attempt may authenticate. Once Finished
claims the session, later failure is terminal with no reconnect/fallback.
Each connection keeps its own immutable completed identity/binding; failed
provisional fields cannot mutate the boot pins or the next attempt.

The existing fully injected `New(Options)` retains its exact two-field readiness
prelude and current behavior. Internally extract only the connection preparation
step needed by both constructors, followed by the same session handshake,
encrypted readiness validation, timers, revocation and joined stream closure.
No change to session cryptography, historical v2 or generation-gate meaning.

## Entropy and actual entrypoint selection

The selected bootstrap path must not default to blocking `crypto/rand.Reader`.
Its Linux reader calls `getrandom(..., GRND_NONBLOCK)` for each exact 32-byte
ephemeral key request, with one bounded syscall, no waiting or retry loop. Any
EAGAIN/EINTR/error/short read zeroes the partial output and fails with a fixed
error. No `/dev/urandom`, blocking retry, helper process or random fallback is
allowed. The dependency can be injected for pure tests, but no environment or
public CLI option chooses entropy. Existing `New(Options)` defaults remain
unchanged. This establishes the intended call semantics, not measured live
early-boot entropy availability.

GREEN fills the private entrypoint dependencies with the bounded reader and
selected minimal adapter. The tested routing helper reads and validates once
before constructors. Absence invokes the unchanged legacy runner; valid
presence invokes only the minimal runner with the same immutable source bytes;
invalid presence or read error invokes neither. The concrete minimal adapter
parses those retained bytes into `BootConfig` and constructs `NewBootstrap`;
it never reopens `/proc/cmdline`. This small duplicate parse keeps the private
original RED seam independent of the later public type, without another source.

No legacy port1024 listener, exec/copy backend, environment-derived proxy
configuration or v1 transport is constructed on selected minimal input. Signal
cancellation feeds the minimal server's existing lifetime. The only advertised
capability stays `authenticated_minimal_control`; no workload or credential
operation appears in this slice.

Ownership and remaining dependencies:

- The separately approved `vsock.ListenLinuxControl()` on port1025 reuses the existing
  private Linux listener construction. Keep `ListenLinux()` fixed at1024 and
  legacy behavior unchanged; do not expose an arbitrary-port API or duplicate
  transport implementation. A narrow AST test checks the fixed constructors
  and selected bind argument without invoking them. Actual AF_VSOCK availability
  is not tested. The non-Linux implementations fail closed.
- Root PID1 must subsequently validate the same minimal boot config **before**
  network configuration/start-gate release/child creation. The current untagged
  L7 PID1 validates only L7 keys and ignores these minimal keys. The agent's
  validation prevents v1 fallback but does not establish root validation.
  That separate PID1 change needs its owner's approval, unchanged absence
  behavior, tests, rebuilt exact guest binaries/image and inspection. No PID1
  or tools/image file is changed here.

The exact later PID1 sequence is `ReadLinuxBootCommandLine(ctx)`, then
`ParseBootCommandLine(retainedLine)`. Any read/parse error must stop before
`guestnetwork` setup, start-gate release, or child construction. Only
`selected == false && err == nil` preserves legacy absence. The opaque
`BootConfig` has no caller-settable fields or JSON authority. Other boot parsers
should consume the same retained public line; they must not obtain a second
independent 4-KiB budget. This package does not implement that PID1 sequence.

The later host producer/transport owner also retains config/process/socket/L7
authority and enforces currentness/loss. Neither this parser nor a guest ACK
is host teardown, network enforcement, credential usability, UID separation,
seccomp, Jailer proof or strict-default admission. Host-network/Jailer NIC
correlation and all credential/exec/copy/terminal acceptance remain later work.

## RED evidence and GREEN checks

`TestMinimalBootstrapREDActualEntrySelectsMinimalBeforeLegacy` requires boot
read then only selected construction. Sixteen malformed/read-failure subcases
require boot validation and neither constructor. At the frozen RED they fail
because the reader is bypassed and the legacy constructor is called. That RED
alone did **not** prove malformed data reached an implemented parser or
provisional handler; the GREEN adds those direct and transcript assertions.
`TestMinimalBootstrapLegacyAbsenceKeepsCurrentConstructor` separately passes.

```sh
go test -p 2 ./cmd/hal-guest-agent -run '^TestMinimalBootstrapRED' -count=1
go test -p 2 -race ./internal/sandboxruntime/microvm/guestagent/minimalcontrol ./cmd/hal-guest-agent -count=10
go test -p 2 -race ./internal/sandboxruntime/microvm/guestagent/... ./cmd/hal-guest-agent -count=3
go vet -p 2 ./internal/sandboxruntime/microvm/guestagent/... ./cmd/hal-guest-agent
```

GREEN executes these assertions unchanged, with direct codec/renderer
and full handshake negatives: all 25 missing/changed prelaunch fields; wrong
nonce/key/runtime/image; duplicate/unknown/aliased/null/noncanonical/oversized
prelude; partial read/write plus cancellation/owner loss/clock expiry at every
new stage; exactly three attempts across provisional failures; third-attempt
success, one claim, no re-admission; bounded entropy errors with zero output;
unchanged fixed constructor/v1/v2 behavior and safe errors. Tests measure
maximum-ID render size and final combined 4096/4097 boundaries without
truncation, with non-Linux fail-closed source/tests and fixed-listener checks.
Cross-compilation of the cmd, minimalcontrol, and vsock test binaries for Darwin
checks build compatibility only; it does not execute non-Linux behavior here.

All new default tests use public synthetic pins, owned in-memory streams,
injected clocks, temporary regular-file/FIFO/symlink fixtures, and bounded
injected entropy. They do not bind AF_VSOCK, read real `/proc/cmdline`, measure
kernel entropy availability, modify host configuration, or activate credentials.
The accepted fixed-constructor transcript tests and original routing RED file
remain unchanged. No historical guard is weakened.

Rebuild/boot/network, credentials and final strict readiness remain unverified even if these pure
and injected gates pass. A required live skip is not acceptance.
