# Sandbox Runtime v2 Phase 43 Credential Delivery Verification

Phase 43 adds fake-safe credential delivery planning, activation, sanitized
projection, and durable metadata surfaces for sandbox runtime v2. The phase
keeps raw credentials out of durable state, distinguishes requested modes from
active modes, and preserves legacy auth-file sync as compatibility-only
metadata.

Phase 43 does not make credential delivery production-active by default. If
Phase 42 network enforcement is absent, network/proxy-dependent delivery
remains planning-only and must not be reported as active credential delivery.

## Implemented Scope

`internal/credentialdelivery` owns credential delivery contracts,
normalization, validation, secret-resolution planning, fake activation
adapters, sanitized activation results, and import-boundary guards. Plans and
activation results carry safe identifiers, enum-like delivery modes, reason
codes, warning/error counts, and sanitized status metadata only.

`internal/sandbox` owns durable public credential delivery status metadata.
The sanitizer preserves safe plan and activation identifiers, requested and
active mode labels, status, reason code, and counts while dropping unsafe raw
credential values, paths, header-shaped strings, token-shaped values, and
domain-shaped secret material.

`internal/sandboxexecution.Manifest`,
`internal/factory.SandboxMetadata`, `internal/sandboxruntime.RuntimeMetadata`,
and `internal/sandboxworker.SecurityControls` can carry optional sanitized
credential delivery metadata. Legacy records without credential delivery
metadata continue to load without new required fields.

Command wiring projects credential delivery status from safe credential proxy
planning inputs for `hal run --sandbox`, `hal auto --sandbox`, and
`hal factory run --sandbox`. This command projection is plan-only: active
modes are not projected unless an explicit sanitized activation result reports
`active`.

Legacy auth sync remains compatibility-only. It may appear in requested modes
when compatibility auth-file sync is requested, but it must not become an
active secure credential delivery mode.

## Verification Commands

Run credential delivery contracts, normalization, validation, planning,
activation, projection, redaction, and import-boundary coverage:

```sh
go test -count=1 ./internal/credentialdelivery
```

Run durable sandbox metadata coverage:

```sh
go test -count=1 ./internal/sandbox
```

Run factory metadata and redaction coverage:

```sh
go test -count=1 ./internal/factory
```

Run non-factory sandbox execution manifest coverage:

```sh
go test -count=1 ./internal/sandboxexecution
```

Run runtime metadata coverage:

```sh
go test -count=1 ./internal/sandboxruntime
```

Run worker metadata coverage:

```sh
go test -count=1 ./internal/sandboxworker
```

Run command-level projection, compatibility, persistence, redaction, and
documentation guard coverage:

```sh
go test -count=1 ./cmd -run 'TestCredentialDelivery|TestCredentialProxyIntent|TestRunSandboxManifestPersistsSanitizedCredentialProxyMetadata|TestAutoSandboxManifestPersistsSanitizedCredentialProxyMetadata|TestRunFactorySandboxExecutorWithDepsPersistsCredentialProxyMetadata|TestPhase43CredentialDelivery'
```

Run the full repository verification stack:

```sh
go test -count=1 -timeout=420s ./...
go vet ./...
make docs-check
make build
git diff --check
```

Run `golangci-lint run ./...` only when `golangci-lint` is installed. If it is
unavailable, report lint unavailable instead of reporting lint as passed.

Passing this matrix satisfies the Phase 43 tests and typecheck gates.

## Fake-Only Scope

Phase 43 verification is fake-only. It does not require real network access,
real proxy servers, upstream API calls, tmpfs mounts, SSH-agent forwarding,
environment secret injection, provider credentials, templates/kits, Docker,
Podman, KVM, Firecracker, root privileges, cloud credentials, worker daemons,
provider/runtime live integration, a live guest, guest-agent transport, vsock,
or a running `hal sandboxd`.

Default Phase 43 tests use pure DTOs, deterministic planner inputs, sanitized
public JSON assertions, fake activation adapters, source guards, parsed
imports, command-boundary fakes, temporary state directories, and explicit
metadata only.

Default Phase 43 verification must not use integration build tags, require
live environment variables, start real proxy servers, bind listener sockets,
perform upstream API calls, create tmpfs mounts, forward an SSH agent, inject
environment secrets, read provider credentials, run template or kit
acquisition, start worker daemons, run `hal sandboxd`, start Firecracker,
access KVM, require root, call Docker or Podman, contact cloud APIs, or depend
on live providers or runtime adapters.

## Focused Test Inventory

Credential delivery package coverage:

- `TestStatusMetadataFromPlanDoesNotProjectActiveModes`
- `TestStatusMetadataFromActivationProjectsActiveModesOnlyForActiveResult`
- `TestCredentialDeliveryImportBoundaries`
- `TestCredentialDeliverySourceGuardOmitsLiveBehaviorMarkers`

Command boundary coverage:

- `TestCredentialDeliveryProjectionAcrossRunAutoAndFactoryIsPlanOnly`
- `TestCredentialDeliveryProjectionRepresentsLegacyAuthSyncAsRequestedOnly`
- `TestCredentialProxyIntentKeepsLegacyAuthSyncRequestedOnly`
- `TestCredentialDeliveryRedactionAcrossDurableSurfaces`
- `TestCredentialDeliveryActivationRedactionForSuccessAndFailure`
- `TestPhase43CredentialDeliveryVerificationDocs`
- `TestPhase43CredentialDeliveryFakeOnlyVerification`

Runtime and worker metadata coverage:

- `TestRuntimeMetadataIncludesOptionalCredentialDeliveryMetadata`
- `TestWorkerSecurityControlsCarryOptionalCredentialDeliveryMetadata`

## Non-Goals

Phase 43 does not implement real proxy servers, upstream API calls, tmpfs
mounts, SSH-agent forwarding, environment secret injection, provider
credentials, templates/kits, OCI template acquisition, real credential broker
delivery, real credential injection, host firewall changes, production microVM
egress, guest network configuration, provider/runtime live integration, or
live E2E credential-delivery verification.

Phase 43 does not make plan metadata, requested modes, legacy auth-file sync,
network proxy session metadata, or compatibility auth sync sufficient to claim
active credential delivery. Active modes are projected only from sanitized
activation results that explicitly report active status.

## Future Handoff Areas

Future phases are responsible for production proxy listener lifecycle, concrete
credential broker adapters, HTTP proxy credential injection, tmpfs-backed file
delivery, SSH-agent forwarding, environment delivery for compatible tools,
provider credential integration, templates/kits, operator diagnostics, and
live E2E verification.

Those phases should keep Phase 43's contract split intact: durable state stores
metadata only, command code remains a projection boundary, runtime and worker
metadata stay sanitized, compatibility auth sync remains explicit, and no
credential value is persisted in sandbox, factory, runtime, worker, or
execution-manifest JSON.

## Review Notes

Keep this document and `cmd/phase43_credential_delivery_docs_test.go` in sync
when focused command selectors, test names, fake-only boundaries, or
credential delivery semantics change. Guard changes should preserve the
fake-only default matrix and should not turn planning metadata into a claim of
live credential delivery.
