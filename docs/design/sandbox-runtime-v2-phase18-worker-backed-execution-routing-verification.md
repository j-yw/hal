# Sandbox Runtime v2 Phase 18 Worker-Backed Execution Routing Verification

Phase 18 covers explicit worker-backed sandbox execution routing for
`rootless_podman` worker hosts. It routes selected worker targets through the
shared command-layer resolver while preserving existing SSH-machine-compatible
defaults, endpoint-safe metadata, fake-only verification, and opt-in real worker
integration coverage.

## Commands

- `hal run --sandbox --sandbox-host <worker-id> --sandbox-runtime rootless_podman`
- `hal auto --sandbox --sandbox-host <worker-id> --sandbox-runtime rootless_podman`
- `hal factory run --sandbox --sandbox-host <worker-id> --sandbox-runtime rootless_podman`

## Routing Boundary

`cmd/sandbox_worker_runtime.go` is the shared command-layer resolver boundary.
Run, auto, and factory execution must route selected worker/rootless targets
through `sandboxWorkerRuntimeDriverFromTarget` instead of constructing worker
clients directly or falling back to SSH-machine driver construction.

Worker-backed execution is opt-in. Unconstrained `hal run --sandbox`,
`hal auto --sandbox`, and `hal factory run --sandbox` must preserve legacy
SSH-machine-compatible resolution and must not list cached worker hosts, require
worker endpoints, attach worker runtime IDs, or construct worker clients.

## Metadata And Contracts

Worker routing metadata uses shared `internal/sandbox.WorkerRoutingMetadata`.
It is attached additively as optional `workerRouting,omitempty` on
`sandboxexecution.Manifest` and as optional `workerRouting` under
`factory.SandboxMetadata`.

Persisted metadata must include only safe selected-route summaries:

- selected worker host id and name
- runtime driver id
- isolation level
- endpoint summary such as `local Unix socket`
- durable requested and enforced security summaries

Raw Unix socket paths, endpoint URLs, hostnames, credentials, URL query strings,
host temp paths, remote temp paths, and local bundle paths must not be persisted
or rendered in command errors.

## Fake-Only Verification Commands

Run focused resolver and route-selection checks:

```sh
go test -timeout=120s ./cmd -run 'TestSandboxWorkerRuntimeResolver|TestWorkerRootless(Run|Auto|Factory)Sandbox(DefaultResolverBuildsClientDriver|UsesSharedWorkerRuntimeResolver)|TestWorkerExecutionRuntimeConstructionStaysCentralized'
```

Run default-preservation checks:

```sh
go test -timeout=120s ./cmd -run 'TestExistingSandboxExecutionDefaultResolversStayWorkerOptIn|Test(Run|Auto|Factory)SandboxDefaultTargetResolutionStaysCachedAndFakeOnly|TestSandboxRuntimeCompat'
```

Run unsupported-runtime, endpoint, and sanitized worker-client failure checks:

```sh
go test -timeout=120s ./cmd -run 'TestWorkerMicroVM|TestWorkerRootless.*Endpoint|TestWorkerClient.*Sanitized|TestSandboxWorkerRuntimeResolver.*(Rejects|Wraps|Sanitizes)'
```

Run output streaming, workspace copy, and recovery artifact checks:

```sh
go test -timeout=120s ./cmd -run 'TestWorkerRootless(Run|Auto)SandboxStreamsOutputAndSummariesExcludePreparation|TestWorkerRootlessFactorySandboxStreamsOutputInOrder|TestWorkerRootless(Run|Auto)SandboxUsesRuntimeCopyForWorkspaceAndArtifacts|TestWorkerRootless(Run|Auto)Sandbox.*Recovery'
```

Run worker-backed security metadata checks:

```sh
go test -timeout=120s ./cmd ./internal/sandboxexec -run 'TestWorkerRootless(Run|Auto|Factory)SandboxUsesSharedWorkerRuntimeResolver|TestRunAttachesCompatibilitySecurityMetadataBeforeTargetReady|TestRunPreservesExistingSecurityMetadataWithoutEvaluationRequest'
```

Run contract and JSON shape checks:

```sh
go test -timeout=120s ./internal/sandbox ./internal/sandboxexecution ./internal/factory ./cmd -run 'TestWorkerRoutingMetadataJSONTags|TestManifestJSONFieldsAndSandboxMetadataTypes|TestSandboxMetadata(LoadsLegacyJSON|OptionalMetadataOmittedWhenNil|RuntimeV2SummaryJSONShape)|TestFactoryStatusDocsIncludeSandboxMetadataJSONFields|TestRunSandboxListJSONPreservesV1ContractForRootlessPodmanRuntime'
```

Run import-boundary checks:

```sh
go test -timeout=120s ./internal/sandboxworker ./internal/sandboxruntime ./internal/sandboxruntime/rootlesspodman ./internal/sandboxexecution ./internal/sandboxexec ./internal/sandboxtarget -run 'Test.*Import|TestPackageImportBoundaries|TestSandboxexecDoesNotImportCommandOrProviderLayers|TestSandboxexecForbiddenImportListCoversRequiredBoundaries'
```

Run the Phase 18 documentation guard:

```sh
go test -timeout=120s ./cmd -run 'TestPhase18WorkerBackedExecutionDocumentationCoversVerificationAndScope'
```

Run build and typecheck verification:

```sh
git diff --check
go test -timeout=300s ./...
go vet ./...
make build
make lint
```

These commands cover fake selected targets, fake worker clients, fake runtime
drivers, git-bundle workspace materialization, temporary `HAL_CONFIG_HOME`
registries, deterministic clocks where command records are saved, command JSON
contracts, import-boundary tests, the full Go package graph, vet, build, and
lint when the linter is installed.

## Optional Integration Check

Real worker-backed rootless Podman coverage is opt-in and build-tagged. It must
skip unless all required environment variables are present:

```sh
go test -timeout=120s -tags=worker_integration ./cmd -run TestWorkerIntegrationRootlessPodmanExecutionThroughSharedResolver -count=1 -v
```

Required variables are `HAL_WORKER_INTEGRATION_ENDPOINT`,
`HAL_WORKER_INTEGRATION_HOST_NAME`,
`HAL_WORKER_INTEGRATION_RUNTIME_DRIVER=rootless_podman`, and
`HAL_WORKER_INTEGRATION_IMAGE`.

## Phase 18 Non-Goals

Phase 18 verification explicitly excludes real network execution, untagged
Podman tests, microVM execution support, changes to default SSH-machine
behavior, Docker workflows, cloud provider access, image pulls, live worker
daemon startup, and provider credential requirements.

Do not run real worker daemons, bind real worker sockets, contact remote worker
hosts, run Podman or Docker workflows without the `worker_integration` tag and
required environment, pull images, access cloud resources, open network
connections, execute microVM runtimes, or change default SSH-machine behavior as
part of Phase 18 story verification.

MicroVM remains unsupported for explicit worker-backed execution in this phase.
Unsupported selected worker runtimes such as `microvm` must fail with a
`runtime_unsupported` classification before provisioning, worker-client
construction, or SSH-machine fallback.

## Review Notes

Worker-backed run, auto, and factory tests should remain fake-only by default.
Use fake selected targets, fake provider-side dependencies where commands still
prepare inputs or reports, fake worker clients, fake runtime drivers, temporary
`HAL_CONFIG_HOME`, and git-bundle workspace fixtures. Preparation output belongs
on setup writers; persisted stdout/stderr summaries should contain only remote
command output from the existing `sandboxexec.EventCommandOutput` path.
