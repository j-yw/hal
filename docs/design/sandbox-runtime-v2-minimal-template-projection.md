# Original selected template identity for minimal launch

Design base `2dab1770e7fcc08260bb8cbce247a3111736d8ed`, including the frozen
original credential request-correlation dependency. This refines the provider
proposal at `7144680c2d8b8ce1112a7a599c64da34e93d6cfc`, not its missing trusted
asset association. The [Linux architecture](sandbox-runtime-v2-linux-completion-architecture.md)
and [L8 reset](sandbox-runtime-v2-l8-credential-runtime-contract-reset.md) govern.
The design at `5cd88b14` and compiling RED `fad1593d` were independently
reviewed before this bounded implementation. The original tuple is copied and
validated without changing provider authority, runtime selection or asset trust.

## Actual gap and digest meanings

`JobStartRequestV2.Exec.Target.Runtime.Image` and
`Runtime.Metadata.TemplateLock` already reach the worker. The request key hashes
their canonical JSON, but a hash cannot supply the original values to the
provider. Current selection hints contain policy IDs, not template/image bytes;
the reservation only exposes its launch identity and original credential pair.

Retain only four comparable strings, not the mutable metadata tree:

```go
type MinimalLaunchTemplateIdentity struct {
    RuntimeImage           string
    TemplateDocumentSHA256 string
    TemplateManifestSHA256 string
    RuntimeImageSHA256     string
}
```

| Proposed field | Original typed request source | Actual meaning |
| --- | --- | --- |
| RuntimeImage | Exec.Target.Runtime.Image | Exact selected runtime reference, including its digest suffix |
| TemplateDocumentSHA256 | Metadata.TemplateLock.Document.DigestValue | Template layer/document bytes; not its OCI manifest |
| TemplateManifestSHA256 | Metadata.TemplateLock.TemplateReference.DigestValue | Selected template OCI manifest, matching L9 Result.ManifestDigest |
| RuntimeImageSHA256 | Metadata.TemplateLock.RuntimeImage.DigestValue | Runtime-image descriptor digest selected by L9; not measured rootfs bytes |

Algorithms, role/kind/status labels are checked constants, not extra mutable
fields. Do not copy timestamps, sizes, reason/warning lists, source-artifact
metadata, trust decisions, capability labels or raw Exec/env into this value.
These do not identify the three named objects. L9's independent acquisition and
trust evaluation still own their meaning; this projection cannot replace them.
The existing public metadata and request-key input retain those other fields.

`registry.ResolveOCIArtifact` measures manifest and layer independently. L9
`selectedManifestDigest` chooses the `metadata.reference` lock, while
`selectedRuntimeImageIdentity` appends the separate `runtime.image` digest to
its reference. Fixtures must deliberately use three different digests. Never
require them to equal, collapse them into one `ImageDigest`, or derive one from
another. Equal byte strings are not independently an error, but carry no proof
that their roles or underlying objects are equal.

## Smallest additive API

Propose one optional final typed argument to existing neutral `ResolveSelection`:

```go
ResolveSelection(ctx, principal, workerID, hints, template ...MinimalLaunchTemplateIdentity)
(*MinimalLaunchReservation).TemplateIdentity() (MinimalLaunchTemplateIdentity, error)
```

Keep the provider interface, original hints, credential correlation, `Reserve`
signature, launch/cleanup identities and receipts unchanged. Resolve copies the
value at entry, before its existing read-only provider callback, and retains it
only on a successful exact prepared selection. Reserve copies that value into
the original reservation. There is no
setter, map, context value, side registry, mutable pointer or new equality field
on a cleanup identity. The provider's retained selection still comes solely from
its own configured policy/asset ownership, never from a request-chosen path.

Zero optional arguments preserve existing neutral compatibility and yield an
unavailable accessor. Exactly one must be complete and valid. Explicit zero,
partial or multiple arguments fail before the provider resolver or issuance.
All public error text remains `ErrMinimalLaunchUnavailable`/existing sanitized
worker errors; never include a candidate image/reference in an error or log.

The accessor rejects nil, zero and copied reservation handles and returns a
value copy only. Like `RequestCorrelation`, it checks original self/shape, not
currentness: an exact retained owner can still read original intent after P,
Revoke, failed Start, selection close, authorizer loss or service loss. Reading
it does not arm, claim, revive or authorize anything. Existing preparation and
owned contexts, callback order and cancellation semantics remain unchanged.

### Presence and validation boundaries

For this projection slice, worker omission means both an empty Runtime.Image
and no TemplateLock. Metadata with unrelated fields alone does not imply a
selected template. Omission remains the existing compatibility call, including
the original minimal foundation tests with unchanged empty-image hints.

If either image or lock is present, require all four values. Each digest is
exactly 64 lowercase hex bytes under literal `sha256`. Require these three
locked tuples without normalizing malformed input into acceptance:

- Document: `oci_artifact / oci_artifact / locked`.
- TemplateReference: `template_reference / oci_artifact / locked`.
- RuntimeImage: `runtime_image / oci_image / locked`.

Require Runtime.Image's only `@` to begin its exact terminal
`@sha256:<RuntimeImageSHA256>` suffix. Retain the original string unchanged;
no trimming, tag substitution or digest synthesis. Bound it to 4096 bytes for
this selected projection. The nonempty prefix starts with an ASCII alphanumeric
byte and contains only ASCII alphanumeric or `._:/-`; reject whitespace/control,
URL schemes, query/fragment, backslash and extra `@`. This is bounded identity
intake, not a second OCI resolver or a promise to support every registry-name
syntax. The future trusted association must compare the entire reference, not
only the suffix, before any use; this value is never passed to a shell or used
to select a local file. Existing generic/legacy reference validators stay put.

The boundary observes the typed request already admitted by the existing worker
decoder; it does not preserve raw JSON spelling or recover data discarded by
the existing metadata sanitizers. No strict/trusted claim may be inferred from
candidate TrustPolicy, absence of warnings or a successful scalar conversion.
Keep existing decoder duplicate/case-alias/size checks; any stronger raw JSON
admission change would require a separate demonstrated need and scope review.

Complete but mismatching trusted image/template expectations can only be
rejected by the component holding those independent expectations. This slice
does not invent them. The later concrete provider must call ClaimLaunch, require
TemplateIdentity and RequestCorrelation, and compare the original tuple with
its retained trusted selection before any host allocation or lease transfer.
Omitted compatibility intent must fail there; it cannot become minimal launch
authority. If concrete selection must reject absence before even read-only
Resolve, its later trusted constructor must explicitly require the projection.
That requirement is not inferred from request metadata, and is not silently
added to old service fixtures by this slice. No fallback or different image is
permitted on missing/mismatching required input.

## Worker capture and original request exactness

Capture the scalar tuple in `handleMinimalLaunch` after existing authenticated
request/safe-ID validation and before request-key computation or any provider
callback. A selected-only pure helper reads the original image and three lock
entries once. Explicit incomplete/inconsistent input returns malformed request
before Resolve, durable IDs, reservation or record publication. Pass the copied
tuple to neutral ResolveSelection, or no argument on genuine omission.

`cloneJobStartRequestV2` does not deep-copy Target metadata. Do not retain or
reread those pointers after callbacks. The tuple and existing canonical request
key must both be captured synchronously from the same ingress snapshot before
Resolve; callback mutations of the caller's metadata must change neither. No
generic immutable-tree framework or alteration to the request-key algorithm is
needed. In-process callers still may not concurrently mutate an input during
admission itself; that is not a supported atomic snapshot API.

The selected store persists RequestKey, not raw image/lock metadata. Existing
final dispatch compares that key to the original reservation and reads back
the complete stored record; pending cancel also checks the original key.
Keep those checks, original credential pair and all retained ownership rules.
Do not claim a new durable template readback or decode the key. There is no
prior-epoch template reconstruction, terminal or recovery behavior in this work.

## Meaningful compiling RED and GREEN scope for later approval

The first RED may add only the four-scalar type, an ignored optional Resolve
argument and an unavailable TemplateIdentity accessor. Keep all existing tests
and hints assertions unchanged. New tests exercise:

1. Actual Reserve/Arm/Start/Claim with an independent current fake selection:
   three distinct original digest roles plus exact reference are unavailable
   today. Copy mutation, loss lifetime and one-shot assertions follow that
   first failure and are not independent RED evidence until reached.
2. Explicit zero/partial/multiple neutral arguments currently enter the real
   resolver; independent omitted-argument Start and wrong issuer/scope controls
   must execute. Capture arguments are scalar copies, not backing slices.
3. Actual authenticated service with a valid lock fixture enters the actual
   provider after durable dispatch, but cannot expose the original tuple.
   Resolver/Current callbacks mutate caller-owned image/lock fields; the future
   accessor and retained original RequestKey must still match pre-callback data.
4. Missing lock/image/each role, wrong kind/status/algorithm, uppercase/short
   digest, mismatching image suffix, malformed/oversize image and explicit empty
   lock currently reach callbacks. Assert zero Resolve/Start/record on rejection.
   Omitted legacy and existing minimal-foundation controls remain operational.
5. Real service exact duplicate versus changed image/document/manifest/runtime
   digest: unchanged original key resolves the same queued job; a changed key
   cannot silently attach to that submission or invoke another provider.
6. After GREEN, nil/zero/copied handles, post-P/revoke/authority/service/selection
   loss, partial failed Start, concurrent copied reads, 4096/4097-byte boundaries,
   all role distinctions and unchanged credential-correlation controls.

No real OCI pull, source build, VM, namespace, credential or cleanup is needed
to reach these local behavioral assertions. A fake expected tuple tests exact
comparison only; it is never called a B1 or verified OCI association.

Candidate production ownership after explicit approval is a dedicated neutral
`minimal_launch_template.go`, the prepared-selection/reservation declarations
and Resolve/Reserve copy points in `minimal_launch*.go`, a selected-only worker
projection helper and `handleMinimalLaunch` call site. Adjacent narrowly named
tests cover them. Any existing normalized source pin must be justified by its
actual declaration delta plus omission/substitution/foreign-getter bypass tests;
no guard update is approved by this design. Generic worker clones, store/schema,
legacy paths, command selection, provider and asset packages are not edited.

## Unresolved trusted handoff

The required association remains an independently approved constructor input
binding this exact template manifest/document/runtime-reference tuple to an
accepted `minimalprofile.Receipt.Expected`, verified L7 parent, local bundle,
and policy/runtime selection. `L8MinimalExpectedIdentity.RootfsSHA256` is the
measured rootfs file, with separate init/agent/source-lock/inspection/provenance
pins. It is not any of the three OCI/template digests above. Only the actual
local verifier/retained launch lease can establish current source possession.

Candidate TemplateLock JSON, catalog entries, diagnostic tar/image output,
descriptorRef text and plain receipts cannot manufacture that association.
This document neither defines an OCI minimal-bundle artifact format nor adds
an asset issuer, path resolver or provider. The accepted provider proposal's
producer, real readiness receiver, L7/J cleanup ordering and receipt-before-
commit dependencies remain separate; strict L8/L10/L11 remain unavailable.

## Source references and verification

References below are relative to the exact base above, not moving line numbers:

- `internal/sandboxworker/types.go`: Target/RuntimeTarget (222/232), Validate (651).
- `internal/sandboxworker/job_v2_types.go`: JobStartRequestV2 (41), Validate (109).
- `internal/sandboxworker/job_helpers.go`: cloneJobExecRequest (47), canonicalJobExecRequest (85).
- `internal/sandboxworker/job_v2_helpers.go`: jobRequestKeyV2 (19), canonical inputs (30), clone (67).
- `internal/sandboxworker/minimal_launch_dispatch.go`: handle (48), final barrier (112), reserve (158).
- `internal/sandboxworker/minimal_launch_cancel.go`: minimalLaunchCancelIdentityMatches (78).
- `internal/sandboxruntime/minimal_launch_admission.go`: ResolveSelection (43), Reserve (132), RequestCorrelation (204), Start (267).
- `internal/sandboxruntime/template_lock.go`: three role entries (45), scalar schema (55), sanitizing JSON (104/113).
- `internal/sandboxtemplate/selection/selection.go`: Result (55), Select (67), Bind (158), image (186), metadata correlation (216), manifest (297).
- `internal/sandboxtemplate/acquisition/registry/resolver.go`: ResolveOCIArtifact (31), separately measured return (89).
- `cmd/sandbox_template_selection.go`: construction binding (188), exact target comparison (227/254).
- `internal/sandboxruntime/microvm/assets/minimalprofile/bundle_linux.go`: trusted PublishRequest (25), separately retained Receipt (39).
- `internal/sandboxruntime/microvm/assets/localresolver/l8_minimal_distribution.go`: trusted expected identity (18), verification (70), exact measured comparison (135).

The original design was verified by source inspection and `git diff --check`.
Compiling RED evidence follows; no acquisition, native build or live runtime ran.

## Compiling RED boundary

The neutral scaffold is exactly the four-string type, an ignored optional final
ResolveSelection argument and an accessor always returning zero/unavailable.
There is no private template storage or validation yet. All old tests, worker
production declarations, source pins, provider hints/interface and Reserve's
credential signature remain unchanged.

Two new RED files exercise actual neutral and authenticated worker calls:

- `internal/sandboxruntime/minimal_launch_template_red_test.go` (199 lines).
- `internal/sandboxworker/minimal_launch_template_red_test.go` (247 lines).

```sh
go test -race -p 2 ./internal/sandboxruntime ./internal/sandboxworker -run '^(TestMinimalReservationTemplateIdentity|TestMinimalLaunchServiceTemplateIdentity)' -count=1 -json
```

Initial run: exit 1, 42 intended failing cases (45 test/subtest failure events
including parents), 14 passing controls, zero skips or race reports. One neutral
and three worker positives reach original Claim; each fails at the unavailable
tuple. Worker positives also reach the independent actual-file dispatch oracle,
all three Current calls and original request-key equality. Resolve/last-Current
mutations change only a separate caller metadata copy, not that oracle. Ten
invalid neutral arguments still enter Resolve; 28 malformed provided worker
image/lock cases still reach callbacks/publication. These are separate reachable
failures, not assertions behind the missing accessor.

Later return-copy/loss/failed-Start accessor assertions remain unreached at RED.
Passing controls independently execute omitted and valid-three-role Start,
issuer/principal/scope rejection, unavailable nil/zero/copy observations and
four existing canonical request-key distinctions. A valid fixture's three role
digests are different and survive the actual metadata sanitizer unchanged; its
candidate trust labels are not treated as acquired OCI/B1 proof.

Existing compatibility/dispatch/cancel/request-correlation/source-guard tests
are selected separately for passing regression evidence; logs and exact frozen
head results accompany the handoff. No source-guard exemption is needed to
compile or reproduce this RED. `go vet` on both packages and formatting/diff
checks passed at that frozen RED. GREEN was separately approved after independent
race repetitions reproduced 135 intended failures and 42 controls, zero skips.

## Bounded implementation and reached follow-up checks

`ResolveSelection` now validates and copies the optional four-scalar value
before any provider callback, retaining it on the exact prepared selection.
`Reserve` copies it into the original self-bound reservation. `TemplateIdentity`
returns only a checked value copy, independent of currentness; it cannot repair
a copied handle, omitted value or revoked launch. A single pure
`ValidMinimalLaunchTemplateIdentity` shares the bounded scalar grammar with the
worker extractor; it is syntax validation, not an asset or credential issuer.

The selected worker reads exactly the three typed locked roles, copies their
digest values and original image before keying or Resolve, and forwards only
that value. Both empty image and absent lock keep the original omission route.
Malformed provided fields fail before any callback, durable allocation or
publication. The existing request-key algorithm, hints, provider interface,
credential Reserve argument, cancellation checks, store and receipts are
unchanged. Typed sanitized intake still cannot recover raw JSON metadata that
the existing decoder discarded; no raw decoder trust claim is added.

Both original 199/247-line RED files remain byte-identical. The formerly
unreached copy, loss and failed-Start assertions now pass. Separate follow-up
tests reach actual neutral and authenticated-service Start/Claim, post-P reads
followed by explicit cancel/service/authorizer loss, concurrent returned copies,
nil/zero/copied handles, 4096 acceptance versus 4097 rejection without truncation,
all digest roles and the precise prefix alphabet. Equal digest bytes keep their
separate roles without inventing cross-role equality or inequality proof. Actual
service duplicates reuse only the original queued job; changed image/document/
manifest/runtime digests or omission neither resolve again nor rewrite its
record. No terminal success is manufactured by those duplicate controls.

The sole changed audited worker declaration is `handleMinimalLaunch`: add the
pure extraction/error gate before the original key, then forward the copied
optional value to the original Resolve call. Its exact declaration pin was
independently reviewed for that delta before replacement, with eight new
omission/substitution/reordering bypass cases and all existing cases preserved;
there is no new typed-call exemption. Existing route, cancellation, durable
readback and scope guards remain required. Fixed-head verification commands,
counts, exact pin review and remaining limits accompany the immutable handoff.

The provider still lacks its trusted OCI/template-to-B1 association and concrete
host allocation, readiness, cleanup and persistence consumers. Valid original
template intent alone does not enable any of them. No native build, OCI pull,
live VM, credential transfer, legacy schema or default selector was changed.
