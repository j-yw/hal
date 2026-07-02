# Sandbox Runtime v2 Phase 28 Security Capability Readiness Projection Verification

Phase 28 projects Phase 27 security capability readiness metadata from
existing safe sandbox, worker, runtime, policy, proxy, and credential metadata,
then surfaces sanitized `capabilityReadiness` output on approved command and
factory metadata surfaces. The phase is metadata-only: it exposes projected
posture for inspection without changing sandbox execution behavior.

Phase 28 surfaces readiness output additively for `hal run --sandbox`,
`hal auto --sandbox`, sandbox runtime JSON summaries, factory sandbox records,
and factory timeline security metadata. When projection inputs are absent or
only compatibility metadata is available, default JSON output continues to omit
`capabilityReadiness`.

## Projection Behavior

Projection helpers live in `internal/sandbox/security_capability_projection.go`
and combine safe metadata from these sources:

- Existing `SandboxSecurity` requested and active security summaries.
- Durable worker and runtime posture metadata.
- Network policy result metadata without raw rule values.
- Network proxy session and policy decision-log metadata.
- Credential proxy plan, session, and binding metadata.

Projected Phase 24 network proxy metadata and Phase 25/26 credential proxy
metadata remain `metadata_only` unless explicit safe runtime or worker ready
metadata is present. Compatibility security summaries and rootless worker
posture summaries do not become readiness proof by themselves. Requested
capabilities without matching explicit ready metadata remain `unsupported`.

`EvaluateProjectedSandboxSecurityCapabilityReadiness` delegates to the Phase
27 evaluator and sanitizes output before any command or factory surface
attaches it. Unsafe identifiers and raw-looking URLs, hostnames, local paths,
socket paths, images, tokens, credentials, and secret values are dropped or
omitted rather than persisted.

## Surfacing Behavior

`hal run --sandbox` and `hal auto --sandbox` attach sanitized projected
readiness to sandbox execution manifests only after safe target metadata is
available. Readiness projection does not add CLI flags, remote command
arguments, target resolution changes, lease behavior changes, sync-out changes,
loop behavior changes, execution result handling changes, or execution
blocking.

Sandbox runtime JSON summaries expose optional readiness only through the
approved security summary field and sanitize readiness before serialization.
Cached runtime status paths stay fake-only and must not contact worker daemons
to compute readiness.

Factory sandbox metadata and timeline security metadata may carry sanitized
readiness output when safe projection inputs are available. Factory run records
and timeline events omit readiness by default. Readiness output does not affect
factory target selection, scheduler filtering, lease acquisition, execution,
status transitions, failure classification, or cleanup behavior.

## Focused Verification Commands

Run projection schema, security summary projection, worker/runtime projection,
policy/proxy/credential projection, evaluator handoff, and attachment
sanitization coverage:

```sh
go test -timeout=120s ./internal/sandbox -run 'Test(SandboxSecurityCapabilityReadinessJSONField|ProjectSandboxSecurityCapabilityReadinessInput|ProjectSandboxWorkerRuntimeCapabilityReadinessInput|ProjectSandboxPolicyProxyCredentialCapabilityReadinessInput|EvaluateProjectedSandboxSecurityCapabilityReadiness)'
```

Run approved command/factory/runtime security metadata field coverage:

```sh
go test -timeout=120s ./cmd -run 'TestSandboxSecurityCapabilityReadiness(JSONFieldApprovedStructs|MetadataPreservedWhenAttached)'
```

Run `hal run --sandbox` and `hal auto --sandbox` readiness surfacing,
default omission, sanitization, and non-blocking execution coverage:

```sh
go test -timeout=120s ./cmd -run 'Test(RunSandboxCapabilityReadiness|RunSandboxManifestAttachesSanitizedProjectedCapabilityReadiness|AutoSandboxManifestOmitsCapabilityReadinessWhenUnavailable|RunAutoSandboxWithWriterAttachesCapabilityReadinessWithoutChangingExecution)'
```

Run sandbox runtime summary and factory sandbox metadata readiness surfacing,
default omission, redaction, and non-blocking execution coverage:

```sh
go test -timeout=120s ./cmd -run 'Test(SandboxRuntimeStatusJSON(CachedWorkerRuntimeContractStableAndSafe|OmitsCapabilityReadinessWhenSecurityAbsent)|SandboxRuntimeSecuritySummarySanitizesCapabilityReadinessBeforeJSON|FactorySandbox(CapabilityReadinessOmittedByDefault|MetadataAttachesSanitizedProjectedCapabilityReadiness)|RunFactorySandboxExecutorCapabilityReadinessDoesNotChangeExecution)'
```

These focused commands are fake-only. They cover the internal projection path,
approved JSON surfaces, default omission, sanitized attachment, redaction, and
the requirement that readiness metadata does not alter command, runtime
summary, or factory execution behavior.

## Full Verification Commands

Run the full package test pass, empty-run typecheck, vet, documentation check,
build, and whitespace verification before integrating Phase 28:

```sh
go test -count=1 -timeout=420s ./...
go test -count=1 -timeout=300s -run '^$' ./...
go vet ./...
make docs-check
make build
git diff --check
```

`make lint` is optional for Phase 28. Record it only when `golangci-lint`
actually runs successfully in the current environment.

## Fake-Only Scope

Phase 28 verification is metadata-only and fake-only. Tests should use pure
data contracts, JSON marshaling, reflection over struct tags, temporary
stores, fake command dependencies, fake clocks, fake runtime drivers, cached
runtime metadata, factory stores, and seeded unsafe strings.

Phase 28 fake-only verification has no live services, live sockets, live
proxying, live firewall configuration, firewall mutation, credential delivery,
credential injection, tmpfs writes, SSH-agent forwarding, worker daemon,
worker protocol negotiation, provider startup, runtime startup, Docker,
Podman, KVM, microVM, cloud credentials, provider credentials, external
network access, scheduler readiness gates, target-selection rejection, new
command flags, or execution blocking. Default Phase 28 test commands must not
use integration build tags or require live environment variables.

Do not start a live proxy, bind listener sockets, mutate firewall rules,
deliver credentials, inject credentials, write tmpfs secret payloads, forward
SSH agents, start a worker daemon, run `hal sandboxd`, bind real worker
sockets, contact remote worker hosts, change worker protocol contracts, run
Podman or Docker workflows, access KVM devices, access cloud APIs, open
network connections, invoke concrete providers or runtimes, add new CLI flags,
block sandbox execution on readiness output, or reject scheduler or target
selection candidates from readiness output as part of Phase 28 verification.

## Non-Goals

No live proxying is included in Phase 28.
No live proxy implementation is included in Phase 28.
No firewall implementation is included in Phase 28.
No firewall mutation is included in Phase 28.
No firewall rule mutation is included in Phase 28.
No credential delivery is included in Phase 28.
No credential injection is included in Phase 28.
No tmpfs credential delivery is included in Phase 28.
No SSH-agent forwarding is included in Phase 28.
No worker protocol changes are included in Phase 28.
No worker daemon changes are included in Phase 28.
No readiness gates are included in Phase 28.
No scheduler readiness filtering is included in Phase 28.
No target-selection rejection based on readiness is included in Phase 28.
No execution blocking based on readiness is included in Phase 28.
No provider integration is included in Phase 28.
No runtime integration is included in Phase 28.
No new CLI flags are included in Phase 28.

Future phases are responsible for any live proxy support, firewall
integration, credential delivery, worker protocol support, concrete
runtime/provider capability discovery, readiness gate enforcement, scheduler
filtering, target-selection rejection, or execution blocking based on security
capability readiness.

## Review Notes

Keep Phase 28 projection and surfacing metadata-only. Projection belongs in
`internal/sandbox` and should stay independent from command, factory,
provider, runtime adapter, worker client, process, network, Docker, Podman,
KVM, microVM, cloud SDK, HTTP proxy, SSH-agent, and tmpfs dependencies.

Command and factory surfacing should attach only sanitized readiness output to
approved security metadata fields. When Phase 28 test names change, update
this document and the Phase 28 documentation guard together so the focused
fake-only commands keep matching the actual coverage.
