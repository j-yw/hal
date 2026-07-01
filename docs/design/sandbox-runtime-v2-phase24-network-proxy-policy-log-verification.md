# Sandbox Runtime v2 Phase 24 Network Proxy Policy Log Verification

Phase 24 adds data-only, redaction-safe network proxy session and network
policy decision-log contracts for sandbox execution. It gives future policy
debugging a durable metadata shape without adding live network enforcement,
proxy processes, firewall rules, or credential delivery.

## Proxy and Decision-Log Contracts

Proxy and decision-log contracts live in `internal/sandbox/network_proxy.go`.
They model safe proxy session IDs, sources, policy snapshot identity, sanitized
request summaries, destination categories, decision outcomes, reason codes,
policy presets, rule kinds, enforcement mode labels, and explicit enforcement
claims. The structs intentionally omit raw hostnames, IP addresses, ports,
URLs, headers, bodies, tokens, environment values, local paths, socket paths,
credential values, and live runtime/provider details.

Schema coverage lives beside the contracts in `internal/sandbox/network_proxy_test.go`.
Those tests lock JSON field names, `omitempty` behavior, enum values, and raw
field absence before later phases add validation or live enforcement.

Validation and normalization coverage lives in
`internal/sandbox/network_proxy_validation.go` and its tests. Proxy session
validation returns sanitized field errors, trims safe identifiers, canonicalizes
known enum values, and does not infer enforcement metadata when it is absent.
Decision-log validation returns sanitized record-index and field errors,
rejects unsafe request metadata labels, preserves safe destination categories,
and never turns denied outcomes into enforced claims without explicit enforcing
metadata.

Redaction coverage uses the same pure validation package. Sanitizers clear
unsafe dynamic identifiers and labels before durable persistence, preserve safe
enum-like policy/category/source/outcome/reason metadata, and remove
`enforced: true` unless the enforcement mode is an actual enforcing mode such
as `proxy`, `firewall`, `runtime`, or `proxy_firewall`.

Import-boundary coverage lives in
`internal/sandbox/network_proxy_import_boundary_test.go`. The guard scans
production `network_proxy*.go` files only and keeps the Phase 24 contract layer
free of command, compound, factory, worker-client, concrete runtime/provider,
network/process, Docker/Podman, KVM/microVM, and cloud SDK dependencies.

## Metadata Plumbing

Run and auto manifests expose optional proxy/log metadata additively on
`sandboxexecution.Manifest` as `networkProxySession,omitempty` and
`networkPolicyDecisionLogs,omitempty`. Command save helpers sanitize supplied
metadata before persistence, and default manifests omit these fields when no
proxy/log metadata is provided.

Factory sandbox records expose optional proxy-session metadata additively on
`factory.SandboxMetadata`. Factory timeline events expose optional decision
logs additively on `factory.EventRecord`. Factory persistence and status
normalization run the same sandbox sanitizers before JSON is written or
rendered, and default factory records and timeline events omit proxy/log fields.

The compatibility enforcement semantics remain honest. Compatibility-runtime
coverage proves `audit_only`, `none`, `best_effort`, and `legacy_default` are
valid debugging labels but are not enforcing modes for `enforced: true` claims.
Only explicit enforcing modes may preserve an enforced decision-log claim.

## Focused Verification Commands

Run schema coverage:

```sh
go test -timeout=120s ./internal/sandbox -run 'TestNetworkProxyDecisionContractConstants|TestNetworkProxySessionMetadataJSONSchema|TestNetworkPolicyDecisionLogRecordJSONSchema|TestNetworkProxyContractsExposeNoRawRequestFields'
```

Run import-boundary coverage:

```sh
go test -timeout=120s ./internal/sandbox -run 'TestNetworkProxyImportBoundaries|TestNetworkProxyImportBoundaryCoversProductionContractFiles|TestNetworkProxyForbiddenImportListCoversRequiredBoundaries|TestNetworkProxyImportBoundaryAllowsStandardLibraryMetadataHelpersOnly|TestNetworkProxyContractsDoNotExposeLiveRuntimeHelpers|TestNetworkProxyContractSourceOmitsLiveRuntimeOperationMarkers'
```

Run validation, normalization, redaction, and compatibility-runtime coverage:

```sh
go test -timeout=120s ./internal/sandbox -run 'TestNetworkProxySessionValidation|TestNetworkPolicyDecisionLogValidation|TestNetworkProxySessionMetadataSanitization|TestNetworkPolicyDecisionLogSanitization'
```

Run non-factory manifest JSON marshal coverage:

```sh
go test -timeout=120s ./internal/sandboxexecution -run 'TestManifestJSONFieldsAndSandboxMetadataTypes|TestManifestUnmarshalWithoutArtifactMetadata'
```

Run factory JSON marshal coverage:

```sh
go test -timeout=120s ./internal/factory -run 'TestSandboxMetadata(NetworkProxySessionJSONShape|NetworkProxySessionJSONRedactionSafety)|TestEventRecord(NetworkPolicyDecisionLogsJSONFields|OptionalFieldsOmitted)'
```

Run run/auto/factory metadata plumbing coverage:

```sh
go test -timeout=120s ./cmd -run 'TestRunAndAutoSandboxManifests|TestFactory(SandboxMetadata|SandboxPersistentMetadata|Timeline|Status).*Network|TestFactorySandboxSecurityPolicyEventAttachesSanitizedDecisionLogs|TestFactorySandboxNetworkProxyMetadataPlumbingAvoidsLiveAdapterImports'
```

Run the Phase 24 documentation and fake-only guards:

```sh
go test -timeout=120s ./cmd -run 'TestPhase24NetworkProxy(VerificationDocs|FakeOnlyVerification)'
```

Run full package, vet, whitespace, build, and lint verification:

```sh
go test -timeout=300s ./...
go vet ./...
git diff --check
make build
make lint
```

These commands cover schema coverage, validation and normalization coverage,
import-boundary coverage, redaction coverage, JSON marshal coverage,
compatibility-runtime coverage, metadata plumbing coverage, documentation
drift, the full Go package graph, vet, build, lint when installed, and
whitespace checks.

## Fake-Only Scope

Phase 24 verification is fake-only. Tests should use pure data contracts,
JSON marshaling, temporary stores, fake command dependencies, fake runtime
drivers, fake providers where command boundaries require them, fake clocks, and
temporary `HAL_CONFIG_HOME` values.

Phase 24 fake-only verification has no real network calls, live HTTP proxy,
firewall mutation, Docker, Podman, KVM, cloud credentials, worker daemon,
microVM, credential proxy, tmpfs secret delivery, SSH-agent delivery, or
provider credential requirement. Default Phase 24 test commands must not use
integration build tags or require live environment variables.

Phase 24 does not implement a live HTTP proxy, firewall rules, credential
proxying, tmpfs secret delivery, SSH-agent delivery, Podman/Docker/KVM/cloud
integration, or microVM runtime implementation.

Do not start a live HTTP proxy, mutate firewall rules, start a worker daemon,
run `hal sandboxd`, bind real worker sockets, contact remote worker hosts, run
Podman or Docker workflows, access KVM devices, access cloud APIs, open network
connections, configure credential proxying, write tmpfs secret payloads,
forward SSH agents, or require provider credentials as part of Phase 24 story
verification.

## Non-Goals

No live HTTP proxy is included in Phase 24.
No firewall rules are included in Phase 24.
No credential proxying is included in Phase 24.
No tmpfs secret delivery is included in Phase 24.
No SSH-agent delivery is included in Phase 24.
No Podman, Docker, KVM, or cloud integration is included in Phase 24.
No microVM runtime implementation is included in Phase 24.
No default behavior changes are included in Phase 24.

Future phases are responsible for live proxy enforcement, firewall integration,
credential proxy delivery, secret delivery integrations, concrete
runtime/provider integration, and end-to-end network-policy enforcement.

## Review Notes

Keep Phase 24 proxy/log files metadata-only. Safe contract helpers may use
standard library parsing and string helpers, but must not import command
packages, concrete runtime adapters, provider adapters, worker clients,
network clients, process execution, Docker/Podman clients, KVM/microVM helpers,
or cloud SDKs.

Keep durable persistence redaction at the command and factory boundaries that
write manifests, records, timeline events, or status JSON. Default run, auto,
and factory behavior should remain unchanged when proxy/log metadata is absent.
