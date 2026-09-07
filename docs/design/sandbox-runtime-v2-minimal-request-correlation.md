# Original credential request correlation for a minimal reservation

Implemented after DESIGN `590e5c70` and compiling RED `cdb5d6e9`, from
`1e9b2eec247b449fdc0d7b7441058e54452df8c1`. This narrows the
isolated provider design `7144680c`; it does not approve that provider or its
trusted OCI-to-image association. The [Linux architecture](sandbox-runtime-v2-linux-completion-architecture.md),
[L8 reset](sandbox-runtime-v2-l8-credential-runtime-contract-reset.md) and
[controller design](sandbox-runtime-v2-minimal-host-controller.md) remain binding.
The implementation adds only copied request correlation and exact selected
worker comparisons. Public schemas, credential grants and runtime activation
are unchanged; a concrete provider and trusted OCI association remain separate.

## Actual path and missing values

`job_v2_service.go:HandleAuthenticatedRequest` validates the original principal
against the service's retained authority before selecting `handleMinimalLaunch`.
The selected handler validates the request, clones it, and requires strict
minimal IDs, including the original `AdmissionGrantID`, before provider Resolve.
`JobCredentialIntentV2.Validate` already requires a positive
`AdmissionGrantRevision` and valid source/binding intent. Those legacy source and
binding alphabets remain unchanged; this slice carries neither of their arrays.

`job_v2_helpers.go:jobRequestKeyV2` hashes the canonical complete cloned request,
driver, principal and daemon epoch. Both admission fields participate, as do
Exec/template metadata and credential bindings. `credentialIntent()` copies the
original scalar fields and arrays into the existing `JobV2.CredentialIntent`.
Canonical hashing does not authorize the request or let a provider decode its
original fields from the digest. Strict selected IDs already reject whitespace;
there is no trim, remap or newly normalized credential grant in this projection.

`reserveMinimalLaunch` holds the manager mutex, checks the retained store/lock,
allocates distinct job/generation IDs, and obtains the original reservation.
It publishes reserved revision 1 then dispatching revision 2 with exact readback
before ArmDispatch. Provider-binding Start performs final Current and
`checkMinimalDispatch` before calling StartMinimalJob with the preparation
context. The provider must ClaimLaunch before any host allocation.

At DESIGN, neither hints nor the reservation exposed the original credential
admission pair. `LaunchGrantID/LaunchPolicyRevision` are separately
issued launch correlation, not substitutes. The existing selected store rejects
equal launch and credential grant IDs. Matching revision numbers may occur by
coincidence; they must not be required equal or artificially made different.

## Smallest copied value API

Proposed neutral additions, with no JSON tags or mutable reference fields:

```go
type MinimalLaunchRequestCorrelation struct {
    AdmissionGrantID       string
    AdmissionGrantRevision uint64
}

func (selection *MinimalLaunchPreparedSelection) Reserve(
    ctx, ownerContext context.Context,
    workerJobID, jobGeneration, requestKey string,
    deadline time.Time,
    correlation ...MinimalLaunchRequestCorrelation,
) (*MinimalLaunchReservation, error)

func (reservation *MinimalLaunchReservation) RequestCorrelation() (
    MinimalLaunchRequestCorrelation, error,
)
```

Reserve accepts zero or one value, not general options. Omission preserves the
existing neutral call behavior and stores an absent zero value. Exactly one
value requires `ValidMinimalLaunchID(AdmissionGrantID)` and a nonzero uint64
revision; explicit zero/partial values, malformed IDs and multiple values fail
before issuance. Copy the two scalars into one private reservation field, never
retain the caller's variadic slice. After launch ID allocation, equality with
that distinct grant rejects without substitution or a hidden retry.

The selected worker always supplies exactly one complete value from its already
validated cloned request. All old selection hints, Resolve signatures, scope,
selection identity, MinimalLaunchIdentity, cleanup receipts and Recover
signatures remain unchanged. This avoids modifying the immutable full-hints
assertion in `minimal_launch_dispatch_red_test.go:ResolveMinimalSelection`.
Reserve is also the appropriate ownership point independently of that fixture:
read-only asset selection need not consume credential admission intent; the
request key and original job reservation are bound together under the manager.
The one current production Reserve caller is `reserveMinimalLaunch`; existing
neutral direct callers omit the new optional value and retain their behavior.
No post-reservation setter or separate request registry is introduced.

RequestCorrelation returns a value copy only from the original self-checked
reservation, with the same strict shape and grant-distinction validation.
Nil/zero/copied reservations or absent/invalid correlation return zero plus
`ErrMinimalLaunchUnavailable`. Mutating the returned value cannot alter the
original. It must remain readable after P, Revoke, owner/authorizer/service loss,
failed Start or selection Close. Do not gate it on currentness, claim, context
state or selection-open state: pending cancellation compares original identity
after launch authority has already expired. It invokes no callbacks or I/O.

A future concrete provider first calls ClaimLaunch successfully on the original
reservation, then requires this accessor before any allocation. A missing pair
fails that one consumed attempt without allocation; it cannot retry or infer
authority from compatibility omission. Reading the accessor before Claim is
permitted bookkeeping, but is never permission for selected boot or credential
work. The copied pair may later populate the existing
`admissionGrantId` and canonical decimal `admissionRevision` prelaunch fields.
It is only requested correlation, not an issued credential seed, live grant,
broker handle, permission to retrieve secrets, or cleanup proof. Credential
authorization must independently validate the exact request/plan/grant and live
job context after the required runtime readiness. No raw Exec, env, sources,
bindings, paths, endpoints or secret values cross this new API.

## Exact selected worker comparison

Make three narrow changes in the eventual coupled worker slice:

1. `reserveMinimalLaunch` supplies the copied pair to Reserve and verifies the
   accessor equals that original request before creating/publishing the record.
   Continue deriving the durable CredentialIntent from the same cloned request;
   do not change request-key generation or allocate another digest/record field.
2. `checkMinimalDispatch` requires the retained accessor to equal the existing
   in-memory CredentialIntent admission pair before provider entry, and requires
   state.RequestKey to equal the original reservation's RequestKey. The latter
   is explicit in cancel today, but the current final barrier compares memory
   and disk bytes without separately comparing that key to the reservation.
   Preserve its existing entry/job-generation/launch-grant, lock/root and exact
   disk readback checks. Failure retains/poisons/revokes as today. A valid key's
   syntax alone cannot repair a mutated pair or coherent memory/disk replacement.
3. `minimalLaunchCancelIdentityMatches` adds the same comparison without removing
   any current complete launch/selection identity comparison. A changed retained
   memory pair cannot authorize cancellation of the original entry. If memory
   still matches but disk/root authority is lost, existing authorized local
   revocation still occurs; no successor write or durable acknowledgment follows.

The neutral package cannot recompute a raw request digest from two values. The
binding is established by the actual service's one clone, key construction,
one reservation and exact durable readback; arbitrary caller-supplied values are
not themselves evidence. Do not claim a standalone cryptographic request proof.
Duplicate same-submission/same-request handling remains unchanged. A changed
admission ID or revision changes the canonical key and conflicts before another
Resolve/Start; it cannot relabel the retained reservation.

No worker schema or terminal behavior changes. Cleanup/recovery identities keep
the original RequestKey rather than duplicating this pair across every equality
and receipt. A future restart cannot obtain a live accessor from decoded fields:
reacquisition still needs separately approved trusted prior-store/provider
authority. This slice does not implement it.

## Compiling RED plan, before GREEN approval

Add separate tests; preserve every existing RED file and assertion unchanged.
The minimal compiling scaffold adds the value type, optional ignored Reserve
argument and an unavailable accessor, but no private storage or behavior change.
The first actual-service test uses the existing authenticated service/provider
fixture, reaches successful Resolve, both durable publications and actual
Start/Claim, then asks that reservation for the original nondefault pair. It
must fail at the missing accessor result, not at a fixture-construction shortcut.
Later assertions are not RED evidence until reached. Independent valid-start,
wrong-principal/issuer and malformed-request controls execute separately.

Required later reachable cases:

- Compare original request, retained copy, durable CredentialIntent and the
  independently recomputed unchanged request key. Deliberately distinguish
  credential ID/revision from launch ID/revision; also allow equal revisions.
- Mutate caller values after issuance and returned copies; original values stay
  exact. Nil/zero/copied handles fail; omission remains unavailable to consumers.
  Reject zero, partial, multiple, whitespace/control/punctuation-leading,
  65/128-byte IDs; accept exact 1/64-byte boundaries and positive uint64 limits.
- Change only ID or revision for the same submission: conflict, no extra
  provider callback or publication. Foreign principal/issuer remains inert.
- At final Current, replace the durable admission pair and/or its request key,
  or corrupt retained memory while keeping a syntactically valid old key; the
  actual final barrier rejects before Start. Retain uncertain original ownership
  and successor canaries using the existing ordinary-file fixtures.
- While Start is blocked, mutate only the stored-memory pair and issue actual
  cancel: no foreign local revoke or record mutation. With original memory but
  corrupt disk, require original local revoke, no successor write. Read the
  original accessor after failed Start, explicit Revoke, P, parent/authority loss
  and service shutdown; cancellation/partial-owner joins remain unchanged.
- Existing no-correlation neutral Start/Finalize/Recover controls and the full
  selected cancellation/lifetime/legacy service tests remain green. No legacy
  credential source/binding syntax, JSON shape or dispatch path is broadened.

## Proposed source/guard ownership and verification

Future production scope: `internal/sandboxruntime/minimal_launch.go` and
`minimal_launch_admission.go`; `internal/sandboxworker/minimal_launch_dispatch.go`
and `minimal_launch_cancel.go`, plus dedicated new request-correlation tests.
No changes to `job_v2_helpers.go`, request/credential/store schemas or host code.
The three altered worker declarations are exact-source-locked in
`minimal_launch_lifetime_guard_test.go`; their new digests require actual diff
review, not a blanket exception. Add bypass mutations in the adjacent guard
tests for omitted/substituted ID/revision, absent accessor, skipped comparison
and foreign reservation. Preserve every existing bypass and call/receiver guard.
Any further typed-call allowance requires concrete guard-failure review first.

After separate RED review and GREEN approval: actual-service/neutral race three
times, whole adjacent packages, original RED blob checks, full worker source
guards, vet, Darwin compilation, gofmt and diff checks. The original DESIGN was
checked by source inspection and `git diff --check`; RED evidence follows below.

## Still missing: immutable template identity and trusted asset association

This two-scalar projection does not expose or compare the requested immutable
template. The existing request carries runtime Image and optional
`Exec.Target.Runtime.Metadata.TemplateLock` document/template-reference/runtime-
image digest metadata; the canonical request key covers them. L9's measured
`selection.Result.ManifestDigest`, RuntimeImage and RuntimeMetadata are distinct
selection inputs, not a live minimal-image possession capability. Policy ID
equality does not compare those identities, and metadata may be absent on
compatibility paths. The exact minimal-only required digest-role projection,
absence rejection and comparison against independently selected inputs need a
separate reviewed contract; do not pass mutable metadata pointers here.

The constructor-owned association between that verified OCI template/descriptor
identity and independently accepted `minimalprofile.Receipt.Expected`, retained
local bundle/L7 parent and exact policy scope remains unapproved. OCI manifest,
template document, descriptor/distribution documents and raw rootfs are different
digest objects. Never equate them or infer the association from candidate JSON,
the source catalog or a diagnostic image. No new OCI acquisition or provider
selection is authorized by this request-correlation design.

## Compiling RED evidence

```text
go test -race -p 2 ./internal/sandboxruntime ./internal/sandboxworker \
  -run '^(TestMinimalReservationRequestCorrelation|TestMinimalLaunchServiceRequestCorrelation)' \
  -count=1 -json
```

The actual run exits 1 with 13 intended failing leaves (16 failure events
including parents), 11 passing controls, zero skips and no race reports.
Three leaves reach the unavailable accessor after actual Start/Claim: two
neutral original-value cases and one authenticated service/durable-dispatch
case. Seven leaves show explicitly invalid optional values still issue a
reservation. Three independently reach final Current after both actual store
publications: coherently changing the retained memory and ordinary-file request
key, credential grant or credential revision still enters the provider. No
process, credential or host allocation occurs in any fixture.

The later successful-accessor copy/revoke/selection-close and failed-Start
assertions are not yet reached and are not RED evidence. The three final-barrier
cases independently confirm retained uncertain ownership and no rewrite of
their replacement data. Omitted-argument actual Start, nil/zero/copied observation,
wrong issuer/principal and malformed admission controls execute independently.
Those controls plus unchanged dispatch/cancel/binding/lifetime/selected guard
tests pass race three times: 783 passing events, zero failures/skips. Scoped vet
and both actual production-source audits pass (six test/subtest events).
At that checkpoint, no existing RED file, worker production code or guard digest
was edited.

## GREEN scope and verification boundary

The approved four production files now copy exactly one valid supplied pair at
Reserve, retain omission compatibility, and expose only immutable original
correlation after loss. The three selected worker declarations compare the
original pair and request key without changing their existing identity, store,
publication, cancellation or partial-owner ordering. No new typed-call exemption
was needed: only their three exact declaration digests changed, with 14 added
bypass cases and every existing guard retained.

Both frozen RED files remain byte-identical and all 27 original test/subtest
events now pass under race, including the previously unreached copy/revocation
and failed-Start assertions. Separate tests cover post-P/real-parent expiry,
service/authority loss, populated copies/concurrent readers, syntax/revision
boundaries, exact duplicate/conflicting requests, retained-memory mismatch,
disk-only corruption, and caller mutation/partial Start. Fixed-head broader
race, package, source-guard, vet and cross-platform results belong in the handoff.
No live credential, runtime, terminal or OCI acceptance is claimed.
