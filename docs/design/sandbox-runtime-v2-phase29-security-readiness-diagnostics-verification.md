# Sandbox Runtime v2 Phase 29 Security Readiness Diagnostics Verification

Phase 29 derives additive, redaction-safe security readiness diagnostics from
Phase 28 `capabilityReadiness` output. The new
`capabilityReadinessDiagnostics` surface gives maintainers a compact advisory
summary of ready, metadata-only, unsupported, blocked, and missing readiness
states without changing sandbox execution behavior.

Diagnostics are advisory only and must not block execution or target
selection. The `wouldBlockStrictGate` fields describe what a future explicit
strict gate would do; Phase 29 does not add such a gate, scheduler filter,
target-selection rejection, or execution blocker.

## Diagnostic Behavior

Diagnostic contracts and derivation logic live in
`internal/sandbox/security_capability_diagnostics.go`. They expose stable
diagnostic codes, severities, classifications, aggregate status, totals,
`advisoryOnly`, `wouldBlockStrictGate`, and safe capability labels only.

Derivation sanitizes readiness output before constructing diagnostics. Unsafe
hostnames, URLs, ports, headers, bodies, tokens, environment values,
credential values, local paths, socket paths, worker endpoints, runtime
endpoints, provider endpoints, image names, and command snippets are omitted
rather than redacted into placeholders.

Phase 29 surfaces diagnostics only on approved security metadata surfaces:

- `sandbox.SandboxSecurity`
- `factory.SandboxSecurityMetadata`
- `SandboxRuntimeSecuritySummary`
- `hal run --sandbox` sandbox execution manifests
- `hal auto --sandbox` sandbox execution manifests
- sandbox runtime status JSON security summaries
- factory sandbox metadata and factory timeline security metadata

When readiness output is absent, default run, auto, runtime-summary, factory
metadata, and factory timeline JSON continue to omit
`capabilityReadinessDiagnostics`.

## Focused Verification Commands

Run internal diagnostic contract, schema, state matrix, ordering, sanitization,
omitempty, JSON-tag, raw-field exclusion, and serialized safety coverage:

```sh
go test -timeout=120s ./internal/sandbox -run 'TestSecurityCapability(ReadinessDiagnostics|SerializedReadinessDiagnostics)'
```

Run runtime summary field approval, cached runtime status surfacing, default
omission, and serialization sanitization coverage:

```sh
go test -timeout=120s ./cmd -run 'Test(SandboxRuntimeStatusJSONSecurityReadinessDiagnostics|SandboxRuntimeSecurityReadinessDiagnostics|SandboxRuntimeSecurityReadinessDiagnosticsJSONFieldApprovedStruct)'
```

Run `hal run --sandbox`, `hal auto --sandbox`, and factory diagnostic
surfacing, default omission, redaction, timeline, and non-blocking execution
coverage:

```sh
go test -timeout=120s ./cmd -run 'Test(RunSandboxManifest(OmitsReadinessDiagnosticsWhenUnavailable|AttachesSanitizedReadinessDiagnostics)|RunSandboxReadinessDiagnosticsDoNotBlockOrAlterExecution|AutoSandboxManifest(OmitsReadinessDiagnosticsWhenUnavailable|AttachesReadinessDiagnosticsFromSanitizedReadiness)|AutoSandboxReadinessDiagnosticsDoNotBlockOrAlterExecution|FactorySandbox(MetadataAttachesSanitizedReadinessDiagnostics|TimelineAttachesSanitizedReadinessDiagnostics)|RunFactorySandboxExecutorCapabilityReadinessDoesNotChangeExecution)'
```

Run Phase 29 documentation guard coverage:

```sh
go test -timeout=120s ./cmd -run 'TestPhase29SecurityReadinessDiagnostics(VerificationDocs|FakeOnlyVerification)'
```

These focused commands are fake-only. They cover internal/sandbox diagnostics,
runtime summaries, run/auto/factory surfacing, advisory-only behavior, and
documentation guard coverage for Phase 29.

## Full Verification Commands

Run the full package test pass, empty-run typecheck, vet, documentation check,
build, and whitespace verification before integrating Phase 29:

```sh
go test -count=1 -timeout=420s ./...
go test -count=1 -timeout=300s -run '^$' ./...
go vet ./...
make docs-check
make build
git diff --check
```

`make lint` is optional for Phase 29. Run it only when `golangci-lint` is
available. Record `make lint` as unavailable if `golangci-lint` is missing
instead of treating it as a required failed check.

## Fake-Only Scope

Phase 29 verification is metadata-only and fake-only. Tests should use pure
data contracts, JSON marshaling, reflection over struct tags, temporary
stores, fake command dependencies, fake clocks, cached runtime metadata,
factory stores, production source scans, and seeded unsafe strings.

Phase 29 verification explicitly excludes live cloud, Docker, Podman, KVM,
microVM, network proxy, firewall, credential broker, runtime/provider, and
worker daemon requirements. Default Phase 29 test commands must not use
integration build tags or require live environment variables.

Do not start a live network proxy, bind listener sockets, mutate firewall
rules, deliver credentials, inject credentials, start a credential broker,
start a worker daemon, run `hal sandboxd`, bind real worker sockets, contact
remote worker hosts, run Podman or Docker workflows, access KVM devices,
access cloud APIs, open network connections, invoke concrete providers or
runtimes, add readiness gates, block sandbox execution on diagnostics, or
reject scheduler or target-selection candidates from diagnostics as part of
Phase 29 verification.

## Non-Goals

No live cloud access is included in Phase 29.
No Docker, Podman, KVM, or microVM runtime requirement is included in Phase 29.
No live network proxy is included in Phase 29.
No firewall integration or firewall mutation is included in Phase 29.
No credential broker behavior is included in Phase 29.
No concrete runtime/provider integration is included in Phase 29.
No worker daemon behavior is included in Phase 29.
No readiness gate is included in Phase 29.
No scheduler readiness filtering is included in Phase 29.
No target-selection rejection based on diagnostics is included in Phase 29.
No execution blocking based on diagnostics is included in Phase 29.

Future phases are responsible for any explicit strict readiness gate, scheduler
filtering, target-selection rejection, or execution blocking based on security
readiness diagnostics.

## Review Notes

Keep Phase 29 diagnostics redaction-safe and advisory-only. Diagnostic
derivation belongs in `internal/sandbox` and should stay independent from
command orchestration, factory orchestration, provider adapters, runtime
adapters, worker clients, network clients, process execution, Docker, Podman,
KVM, microVM, cloud SDK, HTTP proxy, firewall, credential broker, SSH-agent,
and tmpfs dependencies.

When Phase 29 test names change, update this document and
`cmd/phase29_security_readiness_diagnostics_docs_test.go` together so the
focused fake-only commands stay aligned with the actual diagnostics coverage.
