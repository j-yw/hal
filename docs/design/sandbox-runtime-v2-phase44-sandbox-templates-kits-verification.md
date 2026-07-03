# Sandbox Runtime v2 Phase 44 Sandbox Templates And Kits Verification

Phase 44 adds a pure, fake-safe sandbox runtime template contract in
`internal/sandboxtemplate`. The package is distinct from `internal/template`
and describes runtime, workspace, network, credential, reference, and setup
metadata only.

## Implemented Scope

`internal/sandboxtemplate` defines contract types, structured YAML/JSON
decoding, normalization, redaction-safe validation, durable sanitization,
digest-pinned reference preservation, data-only projection into existing
sandbox/runtime DTOs, and import-boundary guards.

Projection maps runtime intent into `sandboxruntime.RuntimeState`, workspace
intent into `sandbox.SandboxWorkspace`, network intent into
`sandbox.SandboxNetworkPolicyIntent` and `sandbox.SandboxSecurity`, and
credential requirements into `sandbox.SandboxSecretDeliveryIntent` and
`sandbox.SandboxSecretSecurity`.

Phase 44 does not implement image builds, OCI pulls, Git fetches, runtime
execution, workspace mutation, network enforcement, credential delivery, Docker
AI Sandboxes, Docker Hub requirements, hosted services, or live provider
integration.

## Verification Commands

Run sandbox template contracts, decoding, normalization, validation,
sanitization, projection, and import-boundary tests:

```sh
go test -count=1 -timeout=180s ./internal/sandboxtemplate
```

Run adjacent sandbox and microVM metadata contracts:

```sh
go test -count=1 -timeout=180s ./internal/sandbox ./internal/sandboxruntime/microvm
```

Run Phase 44 documentation guards:

```sh
go test -count=1 ./cmd -run 'TestPhase44SandboxTemplates'
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

## Fake-Only Scope

Phase 44 verification is fake-only. It does not require network access, Docker,
Podman, OCI registries, Git remotes, KVM, Firecracker, root privileges, cloud
credentials, provider credentials, worker daemons, live sandboxd, live proxy
servers, firewall mutation, credential broker delivery, tmpfs mounts, SSH-agent
forwarding, or environment secret injection.

Default Phase 44 tests use pure DTOs, caller-provided byte fixtures, structured
JSON/YAML parsers, sanitized error metadata, deterministic normalization,
import parsing, source guards, and projection into existing metadata structs.

## Focused Test Inventory

- `TestSandboxTemplateContractFieldsAndJSONTags`
- `TestDecodeBytesYAML`
- `TestDecodeBytesJSON`
- `TestNormalizeTemplateTrimsSafeFieldsAndNormalizesEnums`
- `TestValidateTemplateRejectsUnsafeCoreReferencesAndDigestValues`
- `TestValidateTemplateRejectsUnsafeURLsPathsSecretsAndCommands`
- `TestSanitizeTemplateRemovesUnsafeOptionalMetadata`
- `TestSanitizeTemplateOmitsUnsafeRequiredRecords`
- `TestProjectRuntimeStatePreservesBaseAndLaunchDigests`
- `TestProjectWorkspacePreservesModesAndTrustMetadata`
- `TestProjectNetworkPolicyDoesNotClaimEnforcement`
- `TestProjectCredentialRequirementsRequestedOnly`
- `TestSandboxTemplateProductionImportsStayPure`
- `TestSandboxTemplateProductionSourceOmitsLiveBehaviorMarkers`
- `TestPhase44SandboxTemplatesVerificationDocs`
- `TestPhase44SandboxTemplatesUserDocs`

## Future Handoff Areas

Future phases may add template acquisition, OCI artifact resolution, image
builds, kit installation UX, runtime launch integration, production network
enforcement, real credential delivery, and live E2E verification. Those phases
must keep Phase 44's split intact: template contracts stay data-only, live work
belongs behind explicit runtime, resolver, proxy, credential, or worker
boundaries.
