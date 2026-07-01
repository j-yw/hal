# Sandbox Runtime v2 Phase 22 Policy And Secret Broker Verification

Phase 22 establishes the fake-only network policy and secret broker foundation
for sandbox execution. It makes policy intent, effective policy results, secret
delivery metadata, and redaction guarantees explicit without adding real
network enforcement or real credential delivery.

## Network Policy Model

Network policy model contracts live in `internal/sandbox`. The foundation uses
typed policy presets for legacy/default behavior, allow-listed policy,
deny-by-default policy, disabled policy, and no-policy states. These contracts
separate requested policy intent, enforcement capability, and effective policy
result so callers can report what was requested, what can be enforced, and what
is actually effective.

Validation belongs in `internal/sandbox/network_policy_validation.go`.
Validation is data-only. It rejects malformed domains and endpoints,
credential-bearing URL input, unsupported wildcard patterns, and mismatched
reserved endpoint classes while returning sanitized codes and data-decision
metadata only.

## Effective Policy Evaluation

Effective policy evaluation belongs in
`internal/sandbox/network_policy_evaluator.go`. The evaluator derives effective
intent and enforcement mode only from capability metadata. It downgrades
unsupported strict policy to `legacy_default` with `none` enforcement, and
reports sanitized warnings with safe policy identifiers and reason codes.

The evaluator must not perform DNS lookup, socket creation, HTTP calls,
firewall mutation, proxy setup, Docker/Podman calls, worker calls, provider
inspection, or runtime probing. Runtime and factory summaries may project the
optional result metadata, but that projection is additive and does not change
execution behavior.

## Secret Broker Metadata

Secret broker metadata lives in `internal/factory`. `SecretBrokerSessionMetadata`
and `SecretBrokerSecretMetadata` are durable JSON-safe metadata only. They can
record safe IDs, names, sources, required/present state, and requested/active
delivery mode identifiers.

The raw `ResolvedRunSecret.Value` data stays in unexported in-memory session maps.
It is available only through live broker lookup and is discarded through
`CloseSession` or `DiscardSession`. Durable metadata must not add `value` fields
or serialize raw secret payloads.

Delivery mode validation is metadata-only. Supported modes are `env`,
`file_tmpfs`, `ssh_agent`, `http_proxy`, and `legacy_auth_sync`. Validation
normalizes requested and active mode identifiers and returns sanitized
field/index errors without constructing real delivery mechanisms.

## Redaction Guarantees

Redaction guarantees are owned by `RunSecretRedactor` and the store helpers that
apply it at persistence boundaries. Use `Store.SaveRunWithRedactor`,
`Store.AppendEventWithRedactor`, and `Store.AppendLogChunkWithRedactor` when
resolved secret output may cross durable factory state. Artifact collection
paths should route run-record persistence through redacted store helpers.

Representative coverage should prove that broker metadata, run records,
artifact metadata and payloads, timeline events, log chunks, command JSON, and
errors omit raw secret values, credential-bearing URLs, token assignments, query
strings, and secret payload fragments.

## Contracts

docs/contracts examples are updated only when command JSON or durable record
contracts change. Phase 22 command and factory surfaces project policy metadata
additively as `networkPolicyResult` on runtime summaries and `policyResult` on
factory sandbox metadata and timeline maps. Secret metadata surfaces should stay
limited to requested and active delivery mode identifiers.

## Focused Verification Commands

Run network policy model, evaluator, and compatibility security checks:

```sh
go test -timeout=120s ./internal/sandbox -run 'TestNetworkPolicy|TestEffectiveNetworkPolicy|TestSandboxSecurityCompatibility'
```

Run secret broker, redaction, and marshal safety checks:

```sh
go test -timeout=120s ./internal/factory -run 'TestSecretBroker|TestSecretBrokerRedaction|TestSecretBrokerMarshalSafety'
```

Run local config policy and secret parsing checks:

```sh
go test -timeout=120s ./internal/compound -run 'TestSandboxPolicyConfig|TestSandboxConfig'
```

Run command metadata projection and documentation guard checks:

```sh
go test -timeout=120s ./cmd -run 'TestSandboxSecurityMetadata|TestFactorySandboxSecurityPolicyEvent|TestPhase22PolicySecretDocs'
```

Run full package, vet, whitespace, build, and lint verification:

```sh
go test -timeout=300s ./...
go vet ./...
git diff --check
make build
make lint
```

These commands cover pure policy contracts, sanitized policy validation,
effective policy downgrades, compatibility security honesty, secret broker
session lifecycle, delivery mode metadata, redaction and marshal safety, local
config parsing, command/factory metadata projection, documentation drift, the
full Go package graph, vet, build, lint when installed, and whitespace checks.

## Fake-Only Scope

Fake-only scope means tests should use pure data contracts, temporary stores,
fake command dependencies, fake runtime drivers, fake providers, fake clocks,
temporary `HAL_CONFIG_HOME` values, and in-memory broker sessions. Phase 22
verification should not start daemons, create real sandboxes, contact worker
hosts, contact provider APIs, access cloud resources, mutate firewall rules,
bind proxies, forward SSH agents, write tmpfs secrets, or open network
connections.

## Non-Goals

No proxy or firewall enforcement is implemented in Phase 22.
No credential proxying is implemented in Phase 22.
No tmpfs secret files are written in Phase 22.
No SSH agent forwarding is implemented in Phase 22.
No default behavior changes are introduced in Phase 22.
No microVM or container runtime work is included in Phase 22.
No factory rewrite is included in Phase 22.
No raw secret persistence is allowed in Phase 22.

## Review Notes

Keep policy foundations in `internal/sandbox` data-only. Validation and
effective evaluation may use standard library parsing helpers, but should not
import command packages, concrete runtime adapters, provider adapters, worker
clients, Docker/Podman clients, network clients, or cloud SDKs.

Keep secret broker foundations in `internal/factory/secret*.go` metadata-only.
Those files may use standard library helpers and approved root metadata
contracts, but should not import command orchestration, concrete runtime
adapters, provider adapters, worker clients, HTTP proxy implementations, SSH
agent implementations, tmpfs writers, network clients, Docker/Podman clients,
or cloud SDKs.

Preserve legacy security fields while adding optional policy result metadata.
Do not claim deny-by-default enforcement unless explicit capability metadata
supports it. Deep-copy nested policy result, capability, rule, and warning
slices whenever sandbox security metadata is cloned across package boundaries.
