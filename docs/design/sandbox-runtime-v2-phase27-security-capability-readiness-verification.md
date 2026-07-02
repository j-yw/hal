# Sandbox Runtime v2 Phase 27 Security Capability Readiness Verification

Phase 27 adds data-only, redaction-safe security capability readiness
contracts and a pure evaluator for Sandbox Runtime v2 metadata. It classifies
requested capabilities, existing metadata-only network and credential proxy
records, explicit runtime or worker capability metadata, and explicit blocker
metadata without adding live enforcement, credential delivery, worker protocol
changes, provider/runtime integration, new CLI flags, or persistence behavior.

## Readiness Contracts

Security capability readiness contracts live in
`internal/sandbox/security_capability.go`. They model readiness states,
capability families, capability names, safe sources, reason codes, warning
codes, requested capability metadata, explicit ready or blocked capability
metadata, safe worker posture labels, readiness input, per-capability results,
and readiness output.

The contract fields intentionally carry only safe identifiers and enum-like
metadata. They omit raw hostnames, URLs, ports, headers, bodies, tokens,
environment values, credential values, local paths, socket paths, worker
endpoints, runtime endpoints, provider endpoints, and live enforcement state.
Schema tests lock JSON field names, `omitempty` behavior, stable enum values,
and raw-field absence before any future phase wires readiness data into
durable command or factory surfaces.

Validation, normalization, and durable sanitization live in
`internal/sandbox/security_capability_sanitize.go`. They return sanitized
field/index errors, trim and lowercase enum-like metadata, preserve only safe
labels, drop unsafe optional values, and avoid echoing rejected raw inputs in
errors or output records.

## Readiness Evaluation

The evaluator lives in `internal/sandbox/security_capability_evaluator.go` and
is pure metadata logic. Phase 27 treats Phase 24 network proxy session and
policy decision-log metadata as `metadata_only` because those records do not
prove live proxy, firewall, or runtime enforcement. It treats Phase 25 and
Phase 26 credential proxy plan, session, and binding metadata as
`metadata_only` because those records do not prove live credential delivery.

Requested network policy, network proxy, credential proxy, secret delivery, or
isolation capabilities become `ready` only when matching explicit ready
metadata from a runtime or worker source is present. Metadata source records,
legacy compatibility security labels, and rootless worker posture summaries do
not become proof of ready capability by themselves. Requested capabilities
without matching explicit support are `unsupported`, and explicit safe blocker
metadata can classify a capability as `blocked`.

The evaluator sanitizes input and output, does not mutate caller-owned input,
and produces deterministic results. It does not inspect live hosts, run
providers, call worker daemons, open network connections, mutate firewall
rules, deliver credentials, or persist readiness results.

## Focused Verification Commands

Run readiness contract schema, enum, JSON tag, omitempty, and raw-field
exclusion coverage:

```sh
go test -timeout=120s ./internal/sandbox -run 'TestSecurityCapability(Readiness|MetadataStatusReasonWarning|SerializedReadiness)'
```

Run readiness evaluator classification, matching, determinism, legacy
compatibility, worker posture, blocker, sanitization, and validation coverage:

```sh
go test -timeout=120s ./internal/sandbox -run 'TestEvaluateSecurityCapabilityReadiness|TestValidateSecurityCapabilityReadinessInputErrorsAreSanitized'
```

Run import-boundary and live-behavior source-guard coverage for the readiness
contract, sanitizer, and evaluator files:

```sh
go test -timeout=120s ./internal/sandbox -run 'TestSecurityCapability(ImportBoundar|Source)'
```

Run Phase 27 documentation guard coverage:

```sh
go test -timeout=120s ./cmd -run 'TestPhase27SecurityCapability(ReadinessVerificationDocs|FakeOnlyVerification)'
```

These focused commands are fake-only and cover readiness contracts, evaluator
behavior, sanitized validation errors, deterministic output, import boundaries,
live-behavior guards, and documentation guards for Phase 27.

## Full Verification Commands

Run the full required verification stack before integrating Phase 27:

```sh
go test -count=1 -timeout=420s ./...
go test -count=1 -timeout=300s -run '^$' ./...
go vet ./...
make docs-check
make build
git diff --check
```

`make lint` is optional for Phase 27. Record it only when `golangci-lint`
actually runs successfully in the current environment. If `make lint` only
prints the install hint or the linter is unavailable, do not treat it as a
required or passing Phase 27 verification command.

## Fake-Only Scope

Phase 27 verification is metadata-only and fake-only. Tests should use pure
data contracts, JSON marshaling, reflection over struct tags, deterministic
metadata fixtures, parsed imports, production source scans, and seeded unsafe
strings.

Phase 27 fake-only verification has no live services, live proxy server, live
firewall configuration, credential delivery, credential injection, tmpfs
writes, SSH-agent forwarding, worker daemon changes, worker daemon, worker
protocol negotiation, provider startup, runtime startup, Docker, Podman, KVM,
microVM, cloud credentials, provider credentials, external network access, new
command flags, or durable persistence behavior.
Default Phase 27 test commands must not use integration build tags or require
live environment variables.

Do not start a live proxy, bind listener sockets, mutate firewall rules,
deliver credentials, inject credentials, write tmpfs secret payloads, forward
SSH agents, start a worker daemon, run `hal sandboxd`, bind real worker
sockets, contact remote worker hosts, change worker protocol contracts, run
Podman or Docker workflows, access KVM devices, access cloud APIs, open
network connections, invoke concrete providers or runtimes, add new CLI flags,
or write command/factory persistence surfaces as part of Phase 27 story
verification.

## Non-Goals

No live proxy implementation is included in Phase 27.
No firewall implementation or firewall rule mutation is included in Phase 27.
No credential delivery is included in Phase 27.
No credential injection is included in Phase 27.
No tmpfs credential delivery is included in Phase 27.
No SSH-agent forwarding is included in Phase 27.
No worker protocol changes are included in Phase 27.
No worker daemon changes are included in Phase 27.
No worker daemon behavior is included in Phase 27.
No provider integration is included in Phase 27.
No runtime integration is included in Phase 27.
No provider/runtime integration behavior is included in Phase 27.
No new CLI flags are included in Phase 27.
No new command persistence behavior is included in Phase 27.
No new factory persistence behavior is included in Phase 27.
No durable manifest, factory record, timeline, or status JSON surfacing is
included in Phase 27.
No security capability readiness gate enforcement is included in Phase 27.

Future phases are responsible for command or factory wiring, durable
persistence surfaces, CLI controls, worker protocol support, concrete
runtime/provider capability discovery, live network enforcement, live proxy
support, firewall integration, credential proxy delivery, tmpfs or SSH-agent
delivery integration, and any enforcement gate that blocks sandbox execution.

## Review Notes

Keep Phase 27 readiness files in `internal/sandbox` as pure metadata logic.
Production readiness files may use only standard-library helpers already
allowed by the import guard and safe sandbox metadata contracts. They must not
import command packages, factory orchestration, concrete runtime adapters,
provider adapters, worker clients, network clients, process execution,
Docker/Podman clients, KVM/microVM helpers, HTTP proxy implementations,
SSH-agent implementations, tmpfs writers, cloud SDKs, or filesystem mutation
helpers.

When Phase 27 test names change, update this document and the later Phase 27
documentation guard together so the focused fake-only commands stay aligned
with the actual readiness contract and evaluator coverage.
