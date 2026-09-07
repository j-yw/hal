# Selected original-channel readiness event codec

## Scope and status

Design only at `347331910718c4f967d27fa7b7624021152813e5`. This refines the
exact `HLMINRD1` layout in the [host-controller design](sandbox-runtime-v2-minimal-host-controller.md)
and the event-codec dependency in the [runtime-constructor design](sandbox-runtime-v2-minimal-runtime-constructor.md).
The [Linux architecture](sandbox-runtime-v2-linux-completion-architecture.md)
and [L8 reset](sandbox-runtime-v2-l8-credential-runtime-contract-reset.md) govern.
There is no publisher, receiver loop, production selection or runtime authority
in this slice. The actual eight-role delegate remains unavailable.

## Exact bytes and vocabulary

All integers use network byte order. The event is exactly `174+n` bytes,
where process-generation length `n` is 1..64: minimum 175, maximum 238.
The existing 512-byte original transport limit and cleanup codec stay unchanged.

| Offset | Field | Exact constraint |
| --- | --- | --- |
| 0 | magic, 8 bytes | `HLMINRD1` |
| 8 | version, u16 | 1 |
| 10 | event sequence, u64 | 1 |
| 18 | launch revision, u64 | 2 |
| 26 | complete selected config SHA-256, 32 bytes | Nonzero; not FC-only or seven-role digest |
| 58 | supervisor generation, 43 bytes | Canonical unpadded URL-base64 of a nonzero 32-byte value |
| 101 | process-generation length, u8 | 1..64 |
| 102 | process generation, n bytes | Minimal-binding ID vocabulary below |
| 102+n | transport generation, u64 | Nonzero |
| 110+n | public session ID, 32 bytes | Nonzero |
| 142+n | readiness binding SHA-256, 32 bytes | Nonzero |

Supervisor syntax reuses `validL8RuntimeOwnerToken` in
`firecrackerhost/l8_runtime_owner_recovery.go`. That existing helper also accepts
an all-zero decoded token; this selected event additionally rejects it without
changing the legacy helper. "Nonzero" means the complete 32-byte value is not
all zero, not that every individual byte must be nonzero.

Process syntax is exactly `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`, as required by
`guestagent/minimalcontrol/codec.go:safeID`. It can reuse
`validL8RuntimeOwnerSafeID` with the stricter 64-byte and alphanumeric-first
checks; the cleanup helper alone permits 128 bytes and leading punctuation.
No new exported guest validator or process-handle issuer is needed. The codec
does not infer an actual manager handle from this syntax or impose a new
`fc-handle-` prefix rule. The later receiver must compare the exact retained
process ID. No trimming, case folding, padding or normalization is performed.

The final digest is the raw 32 bytes of the existing shared
`Binding.Digest(sessionID)` result after its canonical `sha256-` hex prefix is
decoded by the future publisher. This codec does not reproduce that algorithm,
assemble the 27-field binding or certify a supplied digest.

## Narrow private interfaces and ownership

Proposed `firecrackerhost/minimal_control_readiness_event.go` contains:

- `minimalControlReadinessEventV1`: six value fields for config digest,
  supervisor generation, process generation, transport generation, session ID
  and readiness-binding digest. No pointers, maps, public JSON or authority methods.
- `encodeMinimalControlReadinessEvent(event) ([]byte, error)`: validate the
  values and emit fresh owned bytes with fixed magic/version/sequence/revision.
- `decodeMinimalControlReadinessEvent(wire) (minimalControlReadinessEventV1, error)`:
  check the total bound before reading offsets, then the exact header, variable
  length, canonical values and exact final extent. Fail with the zero value and
  existing sanitized `errL8RuntimeOwnerProtocol`; never return partial metadata.

A small Linux-only `minimal_control_readiness_event_linux.go` adds
`decodeMinimalControlReadinessDatagram(wire, ancillary []byte, flags int)`.
It rejects any ancillary bytes and `MSG_TRUNC`/`MSG_CTRUNC` before calling the
same pure decoder. This consumes observations, not a socket: it performs no
recvmsg, file construction, descriptor parsing/closure, allocation of a listener
or transfer of FD ownership. Unrelated kernel receive flags are not authority.
The future actual receiver must bound recvmsg to the existing 512-byte buffer
and close every received right on rejection, including truncated control data;
passing this pure wrapper does not prove that resource cleanup happened.

The decoder copies arrays and owns any retained string bytes. Input mutation
after decoding and output mutation after encoding cannot change the value.
The codec owns no secret/key material or long-lived buffer and emits no values
in error text. Six/seven-role packet encoders, decoders and opcodes are untouched.

## Compiling RED and subsequent gates

After this interface review, add fail-unavailable compiling method stubs and
meaningful encode/decode RED tests using independently assembled golden bytes,
not encoder-to-decoder agreement alone. Preserve old cleanup golden tests and
prove each codec rejects the other's magic. No absent-symbol compile error is
reported as behavioral RED.

The intended matrix covers n=1/64, every truncated prefix, empty/overlimit/extra
or concatenated bytes, wrong magic/version/sequence/revision and their endian
encodings, length 0/65/255/mismatch, canonical and noncanonical supervisor tokens,
all-zero fields, invalid process vocabulary, ancillary bytes, both truncation
flags and combined flags, clean datagrams, copied-input/output independence and
sanitized zero-valued failures. Tests separate assertions actually reached in
RED from negatives that only become meaningful after GREEN.

Syntactically valid field changes remain decoded values, not authentication
failures: byte-swapping a nonzero transport counter can produce another valid
counter. Repeated decoding of the same valid datagram also succeeds. Tests lock
this stateless boundary; no replay cache or artificial owner is added here.
Focused default/race tests, unchanged cleanup-codec controls, relevant source
guards, vet and Darwin compilation are the local gates. No socket, subprocess,
namespace, VM, credentials or external service is required for these tests.

## Required later stateful consumer

Only the original private channel after its exact revision-2 reply may adopt
one event. Its sole retained reader must reject duplicates/unsolicited data,
observe EOF/loss, compare config/supervisor/process/transport identity against
independently retained authority, rebuild the shared binding and verify its
session-bound digest. Publication must use the accepted exact A and D deadlines;
ongoing currentness uses the retained hard lifetime H. The receiver then owns
the revocable readiness handle, not this decoded value. Reconnect cleanup Inspect,
a copied event or a successful codec result cannot restore readiness, authorize
credentials/workload, prove L7 ownership or establish terminal cleanup.

## Compiling RED checkpoint

The approved private value type and three fail-unavailable functions now
compile, without changing any existing codec, dispatcher or runtime consumer.
The focused race run reproduced six expected test failures: independent golden
encode/decode, then the valid prerequisites for malformed-wire, value-vocabulary,
ownership/stateless and Linux datagram matrices. The two independent controls
passed: golden offsets/canonical supervisor bytes and the existing exact
revision-2 bootstrap reply/legacy role validation. No tests skipped.

The later mutation, extent, ownership and ancillary assertions are deliberately
unreached at these positive prerequisites in RED; they are not yet verification
of an implemented validator. The unchanged existing owner-protocol/typed-body
selector passed 114 test/subtest events across three race repetitions, zero skips.

```text
go test -p 2 -race -count=1 ./internal/sandboxruntime/microvm/firecrackerhost -run '^TestMinimalReadinessEvent'
go test -p 2 -race -count=3 ./internal/sandboxruntime/microvm/firecrackerhost -run '^Test(L8RuntimeOwnerProtocol|L8RuntimeOwnerTypedBodies)'
```

The first command is intentionally RED. Neither command performs socket I/O,
namespace/process operations, launch or credential activation. GREEN remains a
separate reviewed implementation of these bounded pure interfaces only.
