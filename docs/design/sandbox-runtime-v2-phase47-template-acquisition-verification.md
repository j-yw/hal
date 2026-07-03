# Sandbox Runtime v2 Phase 47 Template Acquisition Verification

Phase 47 adds local YAML/JSON and fake OCI-like sandbox template acquisition
for sandbox runtime templates.

## Implemented Scope

`internal/sandboxtemplate/acquisition` owns resolver request/result contracts,
local file acquisition, fake OCI artifact acquisition, deterministic digest
locking, sanitized errors, and import-boundary guards.

Local acquisition records a locked template document digest while preserving
digest-pinned template references and marking mutable runtime image or
workspace references unresolved.

Fake OCI acquisition uses injected resolver fixtures and must not contact a
live registry by default. Fixture metadata can prove immutable template
artifact, runtime image, or source artifact identity; unproven mutable
references stay unresolved.

Durable sanitized lock metadata is exposed only through the additive
`templateLock` JSON field on:

- `internal/sandbox.SandboxRuntimeState.TemplateLock`
- `internal/sandboxexecution.Manifest.TemplateLock`
- `internal/factory.SandboxMetadata.TemplateLock`
- `internal/sandboxruntime.RuntimeMetadata.TemplateLock`

Those surfaces keep the durable categories `document`, `templateReference`,
`runtimeImage`, and `sourceArtifact` with digest/status/reason labels only.

## PRD Conversion Workflow

For this PRD conversion workflow, use `hal convert` without `--granular`.
`--granular` is legacy prompt-shape compatibility and is not required for this
Phase 47 PRD conversion workflow.

Do not run `hal run` as part of the planning phase. Implementation agents
should execute the assigned PRD task and then run focused and full quality
checks.

## Focused Fake-Only Verification Commands

Run acquisition contracts, local YAML/JSON acquisition, fake OCI acquisition,
unsupported-source handling, and import-boundary guards:

```sh
go test -count=1 -timeout=180s ./internal/sandboxtemplate/acquisition
```

Run root sandbox template contracts, decoding, normalization, validation,
sanitization, and projection coverage:

```sh
go test -count=1 -timeout=180s ./internal/sandboxtemplate
```

Run Phase 47 documentation guards:

```sh
go test -count=1 ./cmd -run 'TestPhase47SandboxTemplateAcquisition'
```

Run durable `templateLock` surface and redaction guards:

```sh
go test -count=1 ./cmd -run 'TestPhase47TemplateLock'
```

## Full Quality Commands

Run the full repository verification stack before marking the worker ready:

```sh
go test -count=1 -timeout=420s ./...
make test
go vet ./...
make docs-check
make build
git diff --check
```

Run `golangci-lint run ./...` only when `golangci-lint` is installed. If it is
unavailable, report lint unavailable instead of reporting lint as passed.

## Fake-Only Scope

Default Phase 47 verification is fake-only.

Default Phase 47 verification is fake-only and does not require Docker Hub,
Docker AI Sandboxes, OCI registries, live network access, Docker, Podman, KVM,
Firecracker, cloud credentials, or provider credentials.

Default Phase 47 test commands must not use integration build tags or require
live environment variables. Default `go test ./...` does not run optional live
integration tests.

## Optional OCI/Live Integration Policy

Optional OCI/live integration tests are not part of the default Phase 47
verification path. If a future story adds live OCI integration tests, they must
use the explicit `template_oci_integration` build tag and skip unless required
environment variables are set.

The optional command shape is:

```sh
go test -tags=template_oci_integration ./internal/sandboxtemplate/acquisition
```

## Focused Test Inventory

- `TestLocalResolverResolvesYAMLAndLocksDocumentDigest`
- `TestLocalResolverResolvesJSONAndLocksDocumentDigest`
- `TestLocalResolverDocumentDigestIsDeterministicForIdenticalContents`
- `TestLocalResolverErrorsDoNotLeakAbsoluteLocalPaths`
- `TestOCIResolverUsesInjectedFixtureAndLocksImmutableDigests`
- `TestInMemoryOCIArtifactResolverLeavesUnprovenMutableRefsUnresolved`
- `TestUnsupportedSourceKindReturnsStableSanitizedError`
- `TestSandboxTemplateAcquisitionProductionImportsStayFakeSafe`
- `TestSandboxTemplateAcquisitionProductionSourceOmitsLiveBehaviorMarkers`
- `TestPhase47TemplateLockDurableSurfacesRequireOptionalMetadata`
- `TestPhase47TemplateLockPersistedJSONShapeAndRedaction`
- `TestPhase47TemplateLockUnresolvedMutableReferenceIsPersistedSafely`
- `TestPhase47SandboxTemplateAcquisitionUserDocs`
- `TestPhase47SandboxTemplateAcquisitionVerificationDocs`
- `TestPhase47SandboxTemplateAcquisitionOptionalOCIIntegrationDocumentation`

## Future Handoff Areas

Future phases may add production OCI clients, live registry resolution, image
builds, Git source acquisition, runtime launch integration, template kit
installation UX, and end-to-end live verification. Those must stay behind
explicit resolver/runtime boundaries and optional build tags so default
verification remains fake-only.
