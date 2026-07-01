# Sandbox Runtime v2 Phase 17 Target Selection Verification

Phase 17 covers cached target-selection and scheduling foundations for sandbox
execution. It introduces command-agnostic selector contracts, deterministic
cached metadata validation, conservative target-selection CLI flags, runtime
resolver guardrails, and default execution regressions that preserve existing
`hal run --sandbox`, `hal auto --sandbox`, and `hal factory run --sandbox`
behavior.

## Scope

Target selection is a cached metadata decision layer. It reads durable sandbox
and host records through fakeable interfaces, validates explicit sandbox, host,
runtime, and isolation intent, and returns selected metadata or deterministic
failure/provisioning results for command code to consume later.

Phase 17 verification is fake-only. Tests must use fake cached state, fake
default target resolvers, fake runtime drivers, temporary `HAL_CONFIG_HOME`
values, and deterministic clocks where command records are saved.

## Verification Commands

Run focused checks for the target-selection foundation:

```sh
go test -timeout=120s ./internal/sandboxtarget
go test -timeout=120s ./cmd -run 'TestSandboxTargetSelectionFlagHelpStaysConservative|TestSandboxRuntimeInspectionDoesNotBleedIntoExecutionCommands'
go test -timeout=120s ./cmd -run 'TestRunSandboxDefaultTargetResolutionStaysCachedAndFakeOnly|TestAutoSandboxDefaultTargetResolutionStaysCachedAndFakeOnly|TestFactorySandboxDefaultTargetResolutionStaysCachedAndFakeOnly'
go test -timeout=120s ./cmd -run 'TestSandboxRuntimeCompatRejectsUnsupportedSelectedRuntimeDrivers|TestSandboxRuntimeCompatDefaultsToSSHMachineUnlessRootlessExplicit|TestSandboxRuntimeCompatWorkerHostMetadataDoesNotSelectRuntime'
go test -timeout=120s ./cmd -run 'TestPhase17TargetSelectionDocumentationCoversVerificationAndScope'
make docs-check
git diff --check
go test -timeout=300s ./...
go vet ./...
make build
make lint
```

These commands cover the `internal/sandboxtarget` import boundary, target
contracts, legacy fallback behavior, explicit host/runtime/isolation
constraints, selected metadata propagation, host-side CLI flag help, runtime
resolver guardrails, default run/auto/factory sandbox regressions, generated
CLI documentation drift, the full Go package graph, vet, build, and lint when
the linter is installed.

Run `make docs-cli` before `make docs-check` when command metadata, examples,
or generated CLI surfaces change.

## Phase 17 Non-Goals

Phase 17 verification explicitly excludes Docker, Podman, KVM, cloud resources,
worker-backed execution, microVM execution, real network tests, and live
runtime refresh.

Do not run real worker daemons, bind real worker sockets, contact remote worker
hosts, run Podman or Docker workflows, pull images, access KVM or other
virtualization devices, access cloud APIs, open network connections, execute
worker-backed runtime drivers, execute microVM runtimes, or run production
sandbox execution workflows as part of Phase 17 story verification.

Live runtime refresh is out of scope for Phase 17. Host and runtime decisions
must come from durable cached metadata supplied through fakeable selector and
command-layer dependencies, not from worker clients, runtime drivers, cloud
providers, Docker, Podman, KVM, or network APIs.

## Review Notes

Unsupported explicit runtime drivers such as `microvm` or worker-only driver
strings may be represented in selected metadata, but Phase 17 must reject them
at runtime driver resolution instead of silently downgrading to SSH-machine
execution. Missing runtime metadata remains the legacy SSH-machine
compatibility path.
