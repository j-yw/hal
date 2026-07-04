# Sandbox Runtime v2 Phase 52 Template Provenance Policy Verification

Phase 52 documents template provenance and trust policy contracts for
production template acquisition.

For Phase 52, production template acquisition requires locked, digest-pinned
references unless explicit advisory mode is selected. Strict mode is the
default production policy and rejects mutable, unresolved, missing, or
inconsistent reference evidence before runtime selection or startup can treat a
template as trusted. Advisory mode must be requested explicitly and records
visible warnings without claiming strict enforcement.

## Implemented Contract Scope

`internal/sandboxtemplate/acquisition` owns data-only trust policy contracts,
strict and advisory evaluation, lock/provenance consistency checks, sanitized
provenance projection, and runtime template-lock trust metadata projection.

The stable public policy shapes are:

- `TrustPolicyRequest`
- `TrustPolicyResult`
- `TrustPolicyError`
- `TrustPolicyWarning`

The supported policy modes are `TrustPolicyModeStrict` and
`TrustPolicyModeAdvisory`.

Strict policy evaluation checks the locked template document identity plus
required template references:

- `metadata.reference`
- `runtime.image`
- `runtime.launch.descriptorRef`
- `workspace.ref`
- `network.policySnapshotReference`

Policy findings use redaction-safe codes only:

- `mutable_reference`
- `missing_digest_pin`
- `unresolved_lock_entry`
- `lock_provenance_mismatch`
- `unsupported_source`
- `resolver_unavailable`

The contracts and projections omit raw local paths, credential-bearing
references, registry auth material, tokens, query strings, command/factory
metadata, concrete runtime drivers, and live startup state.

## Fake/Local Boundary

Default Phase 52 verification is fake/local only.

The default tests use local files, in-memory OCI fixtures, and fake resolvers
only. They do not contact registries, pull images, clone repositories, invoke
signature services, query transparency logs, load key material, start workers,
start sandboxes, or mutate runtime/provider state.

The Phase 52 boundary is that live OCI/registry behavior, hosted registries,
signature services, transparency logs, key management, and broad runtime
rewrites are future or opt-in integration work. They are not part of the Phase
52 default verification matrix and must remain behind explicit
resolver/runtime boundaries if added by a later story.

## Focused Fake/Local Commands

Run the Phase 52 acquisition trust policy contracts, import guards, strict and
advisory evaluator, provenance projection, and runtime metadata projection:

```sh
go test -count=1 -timeout=180s ./internal/sandboxtemplate/acquisition -run 'Test(TrustPolicy|EvaluateTrustPolicy|ProjectTemplateProvenance|ProjectRuntimeTemplateLockMetadata|SandboxTemplateAcquisitionImportBoundaryAllowsTrustPolicyRuntimeMetadataProjection)'
```

Run the Phase 52 command-level durable template-lock trust metadata and docs
guards:

```sh
go test -count=1 -timeout=180s ./cmd -run 'TestPhase52Template'
```

Run the touched fake/local package suites:

```sh
go test -count=1 -timeout=180s ./internal/sandboxtemplate/acquisition ./cmd
```

## Full Quality Commands

Run the full repository verification stack before marking the worker ready:

```sh
go test -count=1 -timeout=420s ./...
make test
go test -count=1 -timeout=300s -run '^$' ./...
go vet ./...
make docs-check
make build
git diff --check
```

Run lint only when `golangci-lint` is installed:

```sh
golangci-lint run ./...
```

`golangci-lint run ./...` only when `golangci-lint` is installed. If it is
unavailable, report lint unavailable instead of reporting lint as passed.

## Focused Test Inventory

- `TestTrustPolicyContractConstantsAreStable`
- `TestTrustPolicyContractFieldsAndJSONTags`
- `TestTrustPolicyJSONShapeIncludesOnlySafePolicyMetadata`
- `TestTrustPolicyJSONOmitsOptionalMetadata`
- `TestTrustPolicyContractsAvoidUnsafeRawMetadataSurface`
- `TestTrustPolicyProductionImportsStayDataOnly`
- `TestTrustPolicyImportBoundaryCoversOnlyPolicyProductionFiles`
- `TestTrustPolicyForbiddenImportListCoversArchitectureBoundaries`
- `TestEvaluateTrustPolicyStrictRejectsUnresolvedRequiredReferences`
- `TestEvaluateTrustPolicyStrictRejectsMissingDigestPinWithoutLockOrProvenance`
- `TestEvaluateTrustPolicyDefaultModeIsStrictProductionRejection`
- `TestEvaluateTrustPolicyStrictRejectsMissingTemplateDocumentIdentity`
- `TestEvaluateTrustPolicyStrictTrustsMatchingLockAndProvenanceEvidence`
- `TestEvaluateTrustPolicyStrictRejectsMissingRequiredLockEntryEvenWithProvenance`
- `TestEvaluateTrustPolicyStrictRejectsProvenanceDigestMismatch`
- `TestEvaluateTrustPolicyAdvisoryReportsWarningsWithoutRejecting`
- `TestEvaluateTrustPolicyAdvisoryReportsMutableAndUnresolvedWarningCodes`
- `TestProjectTemplateProvenanceProjectsLocalLockJSONFields`
- `TestProjectTemplateProvenanceProjectsOCIResolverLocksWithoutUnsafeRefs`
- `TestProjectTemplateProvenanceOmitsUnsafeValuesAndBoundsWarnings`
- `TestProjectRuntimeTemplateLockMetadataSurfacesSanitizedTrustPolicyOutcome`
- `TestSandboxTemplateAcquisitionImportBoundaryAllowsTrustPolicyRuntimeMetadataProjection`
- `TestPhase52TemplateLockTrustPolicyMetadataPersistsSafely`
- `TestPhase52TemplateProvenancePolicyVerificationDocumentation`
- `TestPhase52TemplateProvenancePolicyVerificationCommandsStayFakeLocal`

## Non-Goals

Phase 52 does not add live OCI clients, hosted registry E2E tests, signature
verification, transparency log verification, key management, repository clone
behavior, runtime image pulls, sandbox startup changes, command/factory
orchestration rewrites, broad runtime rewrites, or default integration build
tags.
