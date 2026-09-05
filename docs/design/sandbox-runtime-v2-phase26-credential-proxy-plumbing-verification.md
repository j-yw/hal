# Sandbox Runtime v2 Phase 26 Credential Proxy Plumbing Verification

Phase 26 adds additive, sanitized, metadata-only credential proxy plumbing for
Sandbox Runtime v2 durable records. It projects already-safe Phase 25
credential proxy plan, session, and binding metadata into approved persistence
surfaces without adding live credential delivery, network enforcement, runtime
support, worker support, or credential proxy support beyond metadata
projection.

## Metadata Plumbing Behavior

Credential proxy metadata persists only on these approved surfaces:

- `internal/sandboxexecution.Manifest`
- `internal/factory.SandboxMetadata`

The approved JSON fields are `credentialProxyPlan`,
`credentialProxySession`, and `credentialProxyBindings`, all with
`omitempty`. Phase 26 does not add a standalone `credentialProxy` field.
Default no-metadata records continue to omit `credentialProxy`,
`credentialProxyPlan`, `credentialProxySession`, and
`credentialProxyBindings`.

Non-factory `hal run --sandbox` and `hal auto --sandbox` manifests project
credential proxy metadata from safe command-boundary inputs only: sanitized
network proxy session metadata and typed secret delivery intent. Those
manifests call the Phase 25 credential proxy sanitizers before saving. When no
safe credential proxy metadata is available, the manifest fields remain absent.

Factory sandbox metadata projects from safe factory-side metadata only: safe
secret broker session and secret IDs, sanitized network proxy session metadata,
and typed secret delivery intent. Factory sandbox metadata is sanitized before
record persistence. Factory timeline events do not add or mirror credential
proxy plan, session, or binding metadata.

Command result envelopes, worker metadata, runtime metadata, provider metadata,
and factory timeline event records remain free of direct Phase 26 credential
proxy persistence fields. Factory status may expose credential proxy metadata
only through the existing sandbox metadata record shape, not through timeline
events or command-result envelope fields.

Legacy manifests, factory run records, and factory timeline events without
credential proxy metadata must continue to load and round-trip without adding
credential proxy fields by default.

## Focused Verification Commands

Run credential proxy contract, validation, normalization, sanitization,
network reference, projection, import-boundary, and source-guard coverage:

```sh
go test -timeout=120s ./internal/sandbox -run 'TestCredentialProxy|TestProjectSandboxCredentialProxyMetadata'
```

Run sandbox execution manifest schema and legacy manifest compatibility
coverage:

```sh
go test -timeout=120s ./internal/sandboxexecution -run 'TestManifestJSONFieldsAndSandboxMetadataTypes|TestManifestUnmarshalWithoutArtifactMetadata'
```

Run factory schema, safe secret broker projection, factory projection, and
legacy factory record compatibility coverage:

```sh
go test -timeout=120s ./internal/factory -run 'Test(CredentialProxy|ProjectCredentialProxy|FactoryCredentialProxy|SandboxMetadataCredentialProxy)'
```

Run command-boundary run, auto, factory persistence, redaction, compatibility,
timeline omission, approved-surface guards, import/source guards, unsafe
fixture, and documentation guard coverage:

```sh
go test -timeout=120s ./cmd -run 'Test(RunSandboxManifestPersistsSanitizedCredentialProxyMetadata|RunSandboxCredentialProxyManifestSanitizesProjectionBeforePersistence|AutoSandboxManifest(PersistsSanitizedCredentialProxyMetadata|OmitsCredentialProxyMetadataWithoutSafeSources)|AutoSandboxCredentialProxyMetadataStaysOutOfJSONOutput|RunFactorySandboxExecutorWithDepsPersistsSanitizedCredentialProxyMetadata|RunAndAutoSandboxManifestsOmitCredentialProxyMetadataByDefault|FactoryPersistenceOmitsCredentialProxyMetadataByDefault|Phase26CredentialProxy(LegacyJSONCompatibility|UnsafeFixtureEnumeratesRequiredValueClasses|PersistenceFieldsUseApprovedSurfaces|MetadataRejectedFromUnapprovedSurfaces|MetadataRejectedFromCommandResultEnvelopes|FactoryTimeline(OmissionAfterSanitization|PersistenceAndRenderingOmitMetadata|DocsStateOmission)|Plumbing(GuardsCoverProductionFiles|ImportBoundaries|ForbiddenImportListCoversLiveBehaviorDependencies|ImportBoundaryAllowsCurrentMetadataOnlyDependencies|SourceGuardsOmitLiveBehaviorMarkers|SourceGuardCoversForbiddenMarkers|SourceGuardAllowsSafeMetadataLabels)|VerificationDocs|FakeOnlyVerification))'
```

Run full package, typecheck, vet, whitespace, build, and lint verification:

```sh
go test -timeout=300s ./...
go vet ./...
git diff --check
make build
make lint
```

These commands cover schema, projection, persistence, redaction,
compatibility, guard, and documentation coverage for Phase 26.

## Fake-Only Scope

Phase 26 verification is fake-only. Tests should use pure data contracts, JSON
marshaling, reflection over struct tags, temporary stores, fake command
dependencies, fake factory records, fake clocks, parsed imports, production
source scans, and seeded unsafe strings.

Phase 26 fake-only verification has no real network access, live proxy server,
credential delivery, credential injection, tmpfs mount, SSH-agent forwarding,
firewall mutation, network enforcement, Docker, Podman, KVM, cloud
credentials, worker daemon, microVM, runtime/provider integration, live
credential proxy support, or provider credential requirement. Default Phase 26
test commands must not use integration build tags or require live environment
variables.

Do not start a live proxy, bind listener sockets, mutate firewall rules, start
a worker daemon, run `hal sandboxd`, bind real worker sockets, contact remote
worker hosts, run Podman or Docker workflows, access KVM devices, access cloud
APIs, open network connections, deliver credentials, inject credentials, write
tmpfs secret payloads, forward SSH agents, configure runtime credential proxy
support, or require provider credentials as part of Phase 26 story
verification.

## Non-Goals

No live credential delivery is included in Phase 26.
No credential injection is included in Phase 26.
No live proxy server is included in Phase 26.
No network enforcement is included in Phase 26.
No firewall enforcement is included in Phase 26.
No tmpfs delivery is included in Phase 26.
No SSH-agent forwarding is included in Phase 26.
No worker daemon support is included in Phase 26.
No runtime support is included in Phase 26.
No provider integration is included in Phase 26.
No command-result envelope credential proxy fields are included in Phase 26.
No factory timeline credential proxy fields are included in Phase 26.
No credential proxy support beyond metadata projection is included in Phase 26.

Future phases are responsible for live credential proxy delivery, credential
injection, tmpfs delivery integration, SSH-agent forwarding integration,
network or firewall enforcement integration, worker daemon support, concrete
runtime/provider integration, and any runtime credential proxy support.

## Review Notes

Keep Phase 26 plumbing metadata-only. Production files that project or persist
credential proxy metadata should continue to depend only on safe metadata
contracts and standard-library helpers already allowed by their guard tests.
They must not import command orchestration from data packages, concrete runtime
adapters, provider adapters, worker clients, network clients, process
execution, Docker/Podman clients, KVM/microVM helpers, HTTP proxy
implementations, SSH-agent implementations, tmpfs writers, or cloud SDKs.

When test names change, update this document and
`cmd/phase26_credential_proxy_docs_test.go` together so the documented focused
commands stay in sync with the actual Phase 26 verification coverage.
