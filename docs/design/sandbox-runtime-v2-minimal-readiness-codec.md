# Shared minimal host readiness codec

## Scope and contract

DESIGN/RED only at base `47ddd3ecc069406d57aac21860ee420914feb1e9`.
This is item 1 of the separately frozen controller design `2d8f6585`, not
implementation approval for that controller, eight-FD handoff or producer.
The Linux completion architecture and L8 reset remain authoritative.

Add precisely these pure methods to `guestagent/minimalcontrol.Binding`:

```go
func (binding Binding) EncodeReadinessRequest(requestID string, sessionID [32]byte) ([]byte, error)
func (binding Binding) ValidateReadinessResponse(payload []byte, requestID string, sessionID [32]byte) error
```

They reuse the existing private `readinessRequest`, `decodeReadiness`,
`encodeReadiness`, `Binding.Digest`, canonical request-ID validation and 8192-byte
bound. Encoding returns fresh owned bytes, never a mutable view of the binding.
Validation must not alter its payload or binding. Invalid/zero/decoded bindings,
zero session IDs, noncanonical request IDs and noncanonical response bytes fail
with the existing fixed `ErrInvalid`; an invalid encoder returns nil bytes.
The existing request-ID contract accepts 32 zero hexadecimal characters; this
slice does not invent a nonzero-ID requirement. Session IDs remain nonzero.

The smallest GREEN constructs the existing canonical request from the immutable
binding, expected request ID and session-bound digest. Response validation first
checks its bounded input, then compares it byte-for-byte to `encodeReadiness`
for those exact expected values. That existing encoder remains the sole response
schema and capability-list source. Do not add a second host response struct,
generic JSON decoder, extensibility registry, new capability or crypto protocol.

Canonical equality rejects unknown/duplicate/aliased/escaped keys, field order,
null/type changes, whitespace/trailing/multiple objects, modified request/session/
binding digest, and any capability beyond `authenticated_minimal_control`.
No guest/server/default behavior, wire bytes, protocol counters, readiness owner,
credential state, live transport or runtime proof changes here. A Binding and
validated plaintext remain data, not authenticated/current runtime authority.

## Meaningful compiling RED and preserved controls

The two methods initially return `ErrUnavailable` without accepting input.
`host_readiness_codec_red_test.go` passes the actual pre-existing request through
the unchanged guest decoder and response encoder before calling those stubs.
Thus valid existing guest exchanges demonstrate the missing host functionality;
the RED is not a compile failure or an independent fake encoder's assertion.

The fixed 1161-byte request and 344-byte response golden literals were calculated
independently using Python `hashlib`, sorted fields and big-endian uint16 lengths:
the domain/session/27-field digest input is 963 bytes and its SHA-256 is
`d5fad705eb18587aef8d89fb21ccad1c61436ece8e07843a350ac5ed1300482d`.
The test never invokes Python or a CLI. `TestHostReadinessCodecLegacyGolden`
locks both old codec outputs without calling the new methods.

The RED assertions require host encoding/validation success before mutation,
cross-tuple/session and invalid-argument negatives. At the stub revision those
later assertions are acceptance requirements, NOT negative-validation evidence.
GREEN must reach them unchanged, including all 27 tuple members (runtimeDriver
is a fixed microvm discriminator, not another valid binding), changed request/
session identity, malformed wire categories, constructor-input copying and
caller-payload/output immutability. Existing codec/boot goldens and full guest
server transcript files remain unchanged.

Focused checks, using the pinned Go toolchain and low parallelism:

```sh
go test -p 2 ./internal/sandboxruntime/microvm/guestagent/minimalcontrol -run '^TestHostReadinessCodec' -count=1
go test -p 2 -race ./internal/sandboxruntime/microvm/guestagent/minimalcontrol -skip '^TestHostReadinessCodecRED' -count=3
go test -p 2 -race ./cmd/hal-guest-agent -run '^TestMinimalControl' -count=3
go vet -p 2 ./internal/sandboxruntime/microvm/guestagent/minimalcontrol
git diff --check
```

The first command intentionally fails at RED after the old-codec golden control
passes. Freeze that commit and exact evidence before GREEN. After approval run
the complete new selector, adjacent session/minimalcontrol/guest-entrypoint race
checks, vet and Darwin compilation; the integration owner owns broad gates.
No test here binds real sockets, uses privileged state, executes a VM, activates
credentials or demonstrates an actual host controller consumer.
