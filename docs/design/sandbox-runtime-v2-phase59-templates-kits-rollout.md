# Sandbox Runtime v2 Phase 59 Templates/Kits Rollout

Phase 59 final rollout documentation and fake-only guard barrier for sandbox
templates/kits. It fans in US-001 through US-007: source/reference intake,
deterministic acquisition dispatch, strict/advisory trust policy, durable
selected-template state, worker/runtime projection, secure-default readiness
input, and CLI/status UX.

Default Phase 59 verification is fake-only. The verification surface documents
focused fake-only commands for template acquisition/trust, worker/runtime
projection, secure-default readiness, and CLI/status UX, plus the full quality
commands used before integration.

## Rollout Contract

`internal/sandboxtemplate` owns the data-only template schema,
normalization, validation, sanitization, and selected-template projection
contracts. The `internal/sandboxtemplate` import boundary keeps this package
free of command, factory, provider, concrete runtime, network client, Docker,
Podman, OCI client, Git client, cloud SDK, process execution, and live microVM
dependencies.

`internal/sandboxtemplate/acquisition` owns safe source/reference intake,
local fixture acquisition, injected fake Git/OCI acquisition, resolver
dispatch, deterministic lock metadata, provenance projection, strict/advisory
trust-policy evaluation, and runtime template-lock trust projection. The
`internal/sandboxtemplate/acquisition` import boundary keeps default
acquisition fake-safe and prevents live registries, Git process execution,
Docker/Podman clients, cloud SDKs, worker daemons, sandbox startup, and
credential delivery from entering the default path.

`internal/sandboxworker` projects sanitized selected-template status through
worker status, capabilities, and target metadata. The `internal/sandboxworker`
import boundary keeps worker protocol code command-agnostic and prevents
factory records, command packages, durable sandbox state imports, acquisition
implementation clients, and concrete runtime adapters from entering the worker
protocol layer.

`internal/sandboxruntime` projects sanitized template-lock, provenance, trust,
credential, and network metadata through runtime descriptors. The
`internal/sandboxruntime` import boundary keeps root runtime contracts free of
command/factory orchestration and prevents acquisition implementation clients
from becoming runtime selection logic.

`cmd` and `internal/factory` remain projection, status, persistence, and
formatting boundaries. The `cmd` and `internal/factory` boundary must not
parse template documents, evaluate trust policy, fetch templates, own template
acquisition decisions, rank templates, or select a global secure-default
runtime. Command/status output summarizes the sanitized selected-template
projection already produced by the owning internal packages.

The final guard explicitly covers the `internal/sandboxtemplate` import
boundary, the `internal/sandboxtemplate/acquisition` import boundary, the
`internal/sandboxworker` import boundary, the `internal/sandboxruntime` import
boundary, and the `cmd` and `internal/factory` boundary.

## Secure-Default Non-Goals

Phase 59 does not choose, rank, prefer, or decide the global secure-default
runtime or template. It does not make Docker AI, Docker Hub, an OCI registry,
Git network access, a cloud provider, a live worker daemon, or `hal sandboxd`
part of default verification.

Templates alone do not prove deny-by-default network enforcement, credential
delivery, live runtime isolation proof, or strict secure-default readiness.
Selected-template trust/provenance is one readiness input. Strict
secure-default readiness still requires explicit network, credential, runtime,
workspace, and policy proof metadata from the appropriate proof surfaces.

## Default Fake-Only Verification

Default Phase 59 commands must not use live build tags, Docker/Podman,
registry tools, cloud credentials, raw credential markers, live worker daemons,
network fetches, live registries, shelling out to Git for template
acquisition, `hal run`, or `hal sandboxd`.

Run template acquisition, source/reference intake, trust policy, provenance,
and package import-boundary coverage:

```sh
go test -count=1 -timeout=180s ./internal/sandboxtemplate ./internal/sandboxtemplate/acquisition -run 'Test(ClassifyTemplateSourceReference|TemplateSourceIntake|SandboxTemplateProduction|SandboxTemplateImportBoundary|SandboxTemplateAcquisition|TrustPolicy|EvaluateTrustPolicy|ProjectTemplateProvenance|ProjectRuntimeTemplateLockMetadata)'
```

Run worker/runtime selected-template projection and package import-boundary
coverage:

```sh
go test -count=1 -timeout=180s ./internal/sandboxworker ./internal/sandboxruntime -run 'Test(US005(Worker|Runtime)|SandboxworkerImportsStayCommandAgnostic|SandboxworkerForbiddenImportListCoversCommandCouplingSurfaces|SandboxruntimeImportsStayCommandAgnostic|SandboxruntimeForbiddenImportListCoversCommandCouplingSurfaces)'
```

Run secure-default readiness input, command/factory boundary, overclaim guard,
and CLI/status UX coverage:

```sh
go test -count=1 -timeout=180s ./internal/sandbox ./cmd -run 'Test(US006SelectedTemplate|US006RuntimeStatusProjectsSelectedTemplateTrustReadinessInput|US007(RuntimeStatusJSONSelectedTemplateStates|RuntimeListHumanOutputShowsTemplateTrustProvenanceAndBlockedReasons|RuntimeStatusHumanOutputShowsAbsentSelectedTemplate|SandboxStatusHumanOutputShowsSelectedTemplate)|Phase59)'
```

Run the full quality commands:

```sh
go test ./...
go test -count=1 -run '^$' ./...
go vet ./...
make docs-check
make build
git diff --check
```

`go test -count=1 -run '^$' ./...` is the typecheck-only pass. Run
`golangci-lint run ./...` only when `golangci-lint` is installed; if it is
unavailable, report lint unavailable instead of reporting lint as passed.

## Optional Live Verification

Optional live acquisition behavior is outside default verification. Phase 59
does not add a required live acquisition command. If a future live resolver
check is introduced, document it only in this optional section, require an
explicit environment gate and build tag, and keep it out of default commands,
default CI, and the fake-only release gate.

Optional live checks must skip with sanitized missing-prerequisite diagnostics
before registry access, Git network access, Docker/Podman daemon use, cloud
provider probing, worker daemon use, sandbox startup, credential reads, or
external network egress.

## Barrier Story

| Story | dependsOn | conflictDomains | parallelSafe | barrier |
| --- | --- | --- | --- | --- |
| US-001 | [] | internal/sandboxtemplate; internal/sandboxtemplate/acquisition | false | false |
| US-002 | US-001 | internal/sandboxtemplate/acquisition | false | false |
| US-003 | US-002 | internal/sandboxtemplate/acquisition; internal/sandboxruntime; internal/sandbox | false | false |
| US-004 | US-003 | internal/sandbox; internal/sandboxruntime; internal/sandboxexecution; internal/factory | false | false |
| US-005 | US-004 | internal/sandboxworker; internal/sandboxruntime; cmd | false | false |
| US-006 | US-005 | internal/sandbox; internal/sandboxruntime; cmd | false | false |
| US-007 | US-006 | cmd; docs/cli | false | false |
| US-008 | US-001, US-002, US-003, US-004, US-005, US-006, US-007 | docs/sandboxtemplate; docs/design; cmd; internal/sandboxtemplate; internal/sandboxtemplate/acquisition; internal/sandboxworker; internal/sandboxruntime | false | true |

US-008 is the explicit final docs/guard barrier for Phase 59. Keep this
document, `docs/sandboxtemplate/README.md`, and
`cmd/phase59_templates_kits_rollout_docs_test.go` in sync when selected
template, trust/provenance, fake acquisition, readiness, or CLI/status
contracts change.
