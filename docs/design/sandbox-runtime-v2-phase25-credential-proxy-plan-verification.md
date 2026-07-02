# Sandbox Runtime v2 Phase 25 Credential Proxy Plan Verification

Phase 25 establishes the metadata-only and fake-only credential proxy plan
foundation for sandbox execution. It gives future credential delivery work a
durable, redaction-safe shape without adding live proxying, credential
injection, tmpfs delivery, SSH-agent forwarding, firewall enforcement, worker
daemon changes, or runtime/provider integration.

## Credential Proxy Contracts

Credential proxy contracts live in `internal/sandbox/credential_proxy.go`.
They model safe plan, session, and binding IDs; safe sources; policy snapshot
identity; secret-broker and network-proxy session references; delivery mode
identifiers; request and destination categories; outcomes; statuses; warnings;
and reason codes. The structs intentionally omit raw hostnames, URLs, ports,
headers, bodies, tokens, environment values, local paths, socket paths,
credential values, secret values, and live runtime/provider details.

Schema coverage lives beside the contracts in
`internal/sandbox/credential_proxy_test.go`. Those tests lock enum values,
JSON field names, `omitempty` behavior, and raw field-name absence before later
phases add any explicit persistence or live delivery plumbing.

Validation lives in `internal/sandbox/credential_proxy_validation.go`.
Validation is pure and data-only. It validates safe IDs, safe references, and
explicit enum allowlists while returning sanitized code, field, message, and
optional index metadata only.

Normalization lives in `internal/sandbox/credential_proxy_normalization.go`.
Normalization returns copies, trims ID/reference fields, lowercases enum-like
metadata only, and preserves nil versus explicit empty slices. It must not make
raw-looking hosts, URLs, paths, tokens, or secret markers acceptable.

Durable sanitizers live in `internal/sandbox/credential_proxy_sanitize.go`.
Sanitizers normalize first, return copies, zero records with unsafe required
IDs or references, omit unsafe records from slice helpers, and drop unsafe
optional references instead of replacing them with redaction placeholders.

## Safe References

Secret broker references are bridged from `internal/factory` by
`internal/factory/secret_broker_credential_proxy.go`. That helper copies only
`SecretBrokerSessionMetadata.ID` and `SecretBrokerSecretMetadata.ID` into
sanitized sandbox credential proxy metadata. Broker-style binding `secretId`
references such as `env:GITHUB_TOKEN` are accepted only through the dedicated
secret-reference validator and sanitizer.

Network proxy references live in
`internal/sandbox/credential_proxy_network_proxy.go`. Those helpers copy only
safe network proxy session IDs and safe policy snapshot identity. Request and
destination handling remains limited to Phase 24 safe categories without raw
hosts, URLs, ports, headers, bodies, enforcement metadata, or live proxy state.

## Guard Coverage

Import-boundary coverage lives in
`internal/sandbox/credential_proxy_import_boundary_test.go`. The guard scans
production `credential_proxy*.go` files only and keeps the Phase 25 contract
layer free of command, factory, worker, execution/workspace, concrete
runtime/provider, network/HTTP, process, Docker/Podman, KVM/microVM,
SSH-agent, tmpfs, HTTP proxy, and cloud SDK dependencies.

Live-behavior source guards live in the same test file. They reject
implementation-shaped markers such as listener setup, HTTP proxy construction,
process execution, Docker/Podman/KVM/microVM helpers, SSH-agent helpers, tmpfs
writers, worker clients/daemons, and credential injection helpers while still
allowing safe metadata enum values such as `ssh_agent`, `file_tmpfs`, and
`http_proxy`.

## Unchanged JSON Surfaces

Command JSON, run/auto manifest JSON, factory run record JSON, and factory
timeline event JSON surfaces remain unchanged in Phase 25. No command,
manifest, factory record, or timeline JSON surface gains credential proxy
fields in Phase 25.

Default `hal run --sandbox` and `hal auto --sandbox` manifests omit
`credentialProxy`, `credentialProxyPlan`, `credentialProxySession`, and
`credentialProxyBindings`. Default factory sandbox metadata, factory run
records, and factory timeline events also omit those fields. Explicit future
plumbing phases are responsible for adding sanitized persistence fields when
there is a reviewed durable contract for them.

## Focused Verification Commands

Run credential proxy contract, validation, normalization, sanitization,
network reference, import-boundary, and source-guard coverage:

```sh
go test -timeout=120s ./internal/sandbox -run 'TestCredentialProxy'
```

Run secret broker bridge coverage:

```sh
go test -timeout=120s ./internal/factory -run 'TestCredentialProxyReferencesSecretBrokerMetadataBySafeIDs|TestCredentialProxySecretBrokerHelperDropsUnsafeSecretReferences'
```

Run non-factory manifest, factory persistence, documentation, and fake-only
guard coverage:

```sh
go test -timeout=120s ./cmd -run 'Test(RunAndAutoSandboxManifestsOmitCredentialProxyMetadataByDefault|FactoryPersistenceOmitsCredentialProxyMetadataByDefault|Phase26CredentialProxy(PersistenceFieldsUseApprovedSurfaces|MetadataRejectedFromUnapprovedSurfaces|MetadataRejectedFromCommandResultEnvelopes|FactoryTimeline(OmissionAfterSanitization|PersistenceAndRenderingOmitMetadata|DocsStateOmission))|Phase25CredentialProxy(VerificationDocs|FakeOnlyVerification))'
```

Run full package, vet, whitespace, build, and lint verification:

```sh
go test -timeout=300s ./...
go vet ./...
git diff --check
make build
make lint
```

These commands cover data-only contracts, JSON schema and omission behavior,
safe ID/reference validation, redaction-safe validation errors, normalization,
durable sanitization, safe secret broker references, safe network proxy
references, import boundaries, live-behavior source guards, default no-op
manifest and factory persistence behavior, documentation drift, the full Go
package graph, vet, build, lint when installed, and whitespace checks.

## Fake-Only Scope

Phase 25 verification is fake-only. Tests should use pure data contracts, JSON
marshaling, reflection over struct tags, temporary stores, fake command
dependencies, fake clocks, and seeded unsafe strings.

Phase 25 fake-only verification has no real network access, live proxy server,
credential injection, tmpfs mount, SSH-agent forwarding, firewall mutation,
Docker, Podman, KVM, cloud credentials, worker daemon, microVM, runtime/provider
integration, or provider credential requirement. Default Phase 25 test commands
must not use integration build tags or require live environment variables.

Do not start a live proxy, bind listener sockets, mutate firewall rules, start
a worker daemon, run `hal sandboxd`, bind real worker sockets, contact remote
worker hosts, run Podman or Docker workflows, access KVM devices, access cloud
APIs, open network connections, inject credentials, write tmpfs secret
payloads, forward SSH agents, or require provider credentials as part of Phase
25 story verification.

## Non-Goals

No live proxying is included in Phase 25.
No credential injection is included in Phase 25.
No tmpfs delivery is included in Phase 25.
No SSH-agent forwarding is included in Phase 25.
No firewall enforcement is included in Phase 25.
No worker daemon changes are included in Phase 25.
No runtime/provider integration is included in Phase 25.
No command JSON surface changes are included in Phase 25.
No manifest JSON surface changes are included in Phase 25.
No factory record JSON surface changes are included in Phase 25.
No timeline JSON surface changes are included in Phase 25.

Future phases are responsible for live credential proxy delivery, credential
injection, tmpfs delivery integration, SSH-agent forwarding integration,
firewall enforcement integration, worker daemon support, concrete
runtime/provider integration, and durable command/factory plumbing.

## Review Notes

Keep Phase 25 credential proxy files metadata-only. Safe contract helpers may
use standard library parsing and string helpers, but must not import command
packages, factory orchestration, concrete runtime adapters, provider adapters,
worker clients, network clients, process execution, Docker/Podman clients,
KVM/microVM helpers, HTTP proxy implementations, SSH-agent implementations,
tmpfs writers, or cloud SDKs.

Keep command and factory persistence as explicit no-ops for credential proxy
metadata in Phase 25. Default behavior should remain unchanged until a future
phase adds sanitized persistence fields and tests for those fields.
