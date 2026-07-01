# Repository Guidelines

## Project Structure & Module Organization
- `cmd/`: Cobra CLI commands and flags.
- `internal/`: core packages (`archive/`, `doctor/`, `engine/`, `loop/`, `prd/`, `skills/`, `status/`, `template/`).
- `main.go`: CLI entrypoint wiring.
- `agent-os/`: product/roadmap documentation.
- `docs/contracts/`: versioned machine contract documentation (status-v1, doctor-v1, continue-v1).
- `.hal/`: runtime config created by `hal init` (`config.yaml`, `prd.json`, `progress.txt`, `prompt.md`, `skills/`, `archive/`, `reports/`).

## Build, Test, and Development Commands
- `make build`: compile `hal` with version metadata.
- `make install`: install to `~/.local/bin`.
- `make test`: run unit tests (`go test -v ./...`).
- `make vet`: run `go vet` checks.
- `make fmt`: format code with `go fmt` (gofmt).
- `make lint`: run `golangci-lint` if installed.
- `make run ARGS='--help'`: build and run with arguments.
- Integration tests: `go test -tags=integration ./internal/engine/codex/...` (requires the Codex CLI).

## Coding Style & Naming Conventions
- Go 1.25+ module; keep packages focused and files small.
- Use `gofmt`; indentation and alignment are formatter-controlled.
- File names are lowercase with underscores (e.g., `integration_test.go`).
- Exported identifiers use `CamelCase`; unexported use `camelCase`.
- Prefer explicit error handling and wrap with `%w` when propagating.

## Testing Guidelines
- Tests live alongside code as `*_test.go`.
- Favor table-driven tests for multiple cases.
- Integration tests are tagged `integration` and may skip when Codex CLI is missing.
- Keep tests deterministic; avoid network or CLI dependencies outside tagged tests.

## Commit & Pull Request Guidelines
- Follow Conventional Commits: `feat:`, `fix:`, `refactor:`, etc.
- Include PRD story IDs when applicable (e.g., `feat: US-008 - ...`).
- PRs should explain the change, link the PRD/issue, and list tests run (e.g., `make test`).
- Include screenshots only for CLI output or UX changes.

## Patterns from phase24-network-proxy-policy-log (2026-07-02)

- Proxy session and network policy decision-log foundation contracts belong in `internal/sandbox/network_proxy.go`; keep them data-only and redaction-safe, with safe IDs, sources, policy snapshot identity, request categories, outcomes, and reason codes only, and no raw hostnames, IPs, ports, URLs, headers, bodies, tokens, environment values, local paths, socket paths, credentials, or live proxy/firewall/runtime/provider behavior.
- Schema coverage for proxy/log contracts belongs beside them in `internal/sandbox/network_proxy_test.go`; lock JSON field names, `omitempty` behavior, enum values, and raw-field absence before later validation or manifest-plumbing stories.
- Phase 24 proxy/log import-boundary coverage lives in `internal/sandbox/network_proxy_import_boundary_test.go`; keep it focused on production `network_proxy*.go` files, allow standard-library metadata helpers only, and forbid command, compound, factory, worker-client, concrete runtime/provider, net/http, process, Docker/Podman, KVM/microVM, and cloud SDK dependencies.
- Proxy session validation/normalization belongs in `internal/sandbox/network_proxy_validation.go`; return sanitized code/field errors, expose normalized metadata only for valid input, and do not default absent enforcement metadata to `none` or any live capability claim.
- Decision-log validation/normalization belongs in `internal/sandbox/network_proxy_validation.go`; keep errors record-index/field-oriented and sanitized, reject unsafe request metadata labels, preserve only safe destination categories, and never infer denied decisions as enforced without explicit enforcing metadata.
- Proxy/log durable redaction sanitizers belong in `internal/sandbox/network_proxy_validation.go`; clear unsafe dynamic identifiers/labels before manifest or record persistence, preserve safe enum-like categories/policy/outcome/source metadata, and drop any `enforced: true` claim unless `enforcementMode` is an actual enforcing mode (`proxy`, `firewall`, `runtime`, or `proxy_firewall`), because `none`, `best_effort`, and `audit_only` compatibility metadata are non-enforcing.
- Optional non-factory run/auto proxy-session metadata belongs on `internal/sandboxexecution.Manifest` as additive `networkProxySession,omitempty`; populate it from `cmd` save helpers only after `sandbox.SanitizeSandboxNetworkProxySessionMetadata`, and keep default manifests omitting proxy/log fields.
- Optional factory sandbox proxy-session metadata belongs on `internal/factory.SandboxMetadata` as additive `networkProxySession,omitempty`; populate it from `cmd/factory_sandbox_executor.go` persistence helpers only after `sandbox.SanitizeSandboxNetworkProxySessionMetadata`, and keep default factory records omitting proxy/log fields.
- Optional non-factory run/auto policy decision logs belong on `internal/sandboxexecution.Manifest` as additive `networkPolicyDecisionLogs,omitempty`; populate them from `cmd` save helpers only after `sandbox.SanitizeSandboxNetworkPolicyDecisionLogRecords`, and keep default manifests omitting proxy/log fields.
- Optional factory timeline policy decision logs belong on `internal/factory.EventRecord` as additive `networkPolicyDecisionLogs,omitempty`; sanitize in factory timeline append/status helpers and sandbox policy-event plumbing before JSON persistence or rendering, and keep default timeline events omitting proxy/log fields.

## Patterns from phase23-security-intent-propagation (2026-07-02)

- Pure config-to-evaluator security intent mapping belongs in `internal/sandbox/security_intent.go`; pass only sandbox-native `SandboxNetworkPolicyIntent`, `SandboxNetworkPolicyEnforcementCapability`, and `SandboxSecretDeliveryIntent` metadata, preserve nil-vs-explicit-empty secrets, and keep `security_intent*.go` covered by the `internal/sandbox/network_policy_import_boundary_test.go` pure import guard.
- Compatibility security evaluation belongs in `internal/sandbox/security.go`; when `RequestedNetworkPolicyIntent` is present, derive the legacy `policyRequested` label from the typed intent while using the pure evaluator for `policyResult`, and only claim deny-by-default enforcement when explicit capability metadata supports it.
- Worker security posture mapping belongs at the command boundary in `cmd` adapters such as `sandbox_host_mapping.go` and runtime summaries; derive `SandboxNetworkPolicyResult` from worker `SecurityPolicy` requested/enforced metadata only, and keep `internal/sandboxworker` free of durable `internal/sandbox` imports.
- `hal run --sandbox` config-aware security intent wiring belongs in `cmd`; load local `compound.LoadSandboxConfig` after the project directory is known and before the first run manifest save, then map through `sandbox.MapSandboxSecurityIntent` so absent config preserves legacy deny-by-default/http_proxy metadata and explicit config reaches request and manifest security fields.
- `hal auto --sandbox` config-aware security intent wiring belongs in `cmd`; load local `compound.LoadSandboxConfig` after `ProjectDir` is resolved and before the first auto manifest save, reuse `loadConfiguredSandboxSecurityRequest`, and keep unsupported `--resume` rejected during request parsing before config loading.
- Factory sandbox config-aware security intent wiring belongs in `cmd`; load local `compound.LoadSandboxConfig` in `executeFactoryRun` using the execution repo dir before calling `runSandbox`, pass the resulting `sandbox.SecurityEvaluationRequest` through `factorySandboxExecutorRequest.Security`, and keep `runFactorySandboxExecutorWithDeps` defaulting zero-value requests to legacy deny-by-default/http_proxy metadata for direct fake tests and older call sites.
- Additive security metadata exposure should treat typed `SecurityEvaluationRequest.RequestedNetworkPolicyIntent` and `NetworkPolicyCapability` as non-empty request intent, evaluate request security for SSH-machine compatibility manifests so `policyResult` is present, preserve target active secret modes only for legacy http_proxy defaults, and keep worker/rootless manifest and factory security copied from durable host/runtime posture.
- Phase 23 final security regression barriers belong in `cmd` with fake stores, fake runtimes, and seeded sensitive config/env values; assert redaction on security metadata, factory sandbox metadata/timeline, JSON, and sanitized error surfaces, while avoiding broad full-manifest/full-record local path assertions because legacy top-level `projectDir`/`workDir`/repo fields remain compatibility contract fields.

## Patterns from phase22-policy-secret-broker (2026-07-02)

- Network policy foundation contracts belong in `internal/sandbox/network_policy.go` as data-only typed presets, rules, requested/effective intent, enforcement capability, result, and warning metadata; keep validation, evaluation, enforcement, command wiring, runtime adapters, providers, and workers out of this base contract layer.
- Network policy validation belongs in `internal/sandbox/network_policy_validation.go`; return sanitized validation codes and data-decision metadata only, omit raw rule values, and do not attach enforcement/capability claims from validation.
- Effective network policy evaluation belongs in `internal/sandbox/network_policy_evaluator.go`; derive effective intent and enforcement mode only from requested intent plus `SandboxNetworkPolicyEnforcementCapability`, downgrade unsupported strict policy to `legacy_default`/`none`, and keep warnings limited to safe policy identifiers plus reason/message metadata without raw rule values or runtime side effects.
- Compatibility security metadata belongs in `internal/sandbox/security.go`; preserve legacy `SandboxNetworkSecurity.policyRequested/policyEnforced/enforcementMode` fields while attaching optional `policyResult` from the pure evaluator, and only claim deny-by-default enforcement when explicit capability metadata supports it.
- Phase 22 network policy import-boundary coverage lives in `internal/sandbox/network_policy_import_boundary_test.go`; keep `TestNetworkPolicyImportBoundaries` focused on production `network_policy*.go` plus `security.go`, allowing standard library imports only and forbidding command, factory, runtime adapter, provider, worker, Docker/Podman, network-client, and cloud SDK dependencies.
- In-memory secret broker session foundations belong in `internal/factory/secret_broker.go`; expose only `SecretBrokerSessionMetadata`/`SecretBrokerSecretMetadata` as durable JSON-safe types, keep raw `ResolvedRunSecret.Value` data in unexported live broker maps, and discard it through explicit `CloseSession`/`DiscardSession`.
- Secret broker delivery mode validation belongs in `internal/factory/secret_broker_delivery.go`; support only env/file_tmpfs/ssh_agent/http_proxy/legacy_auth_sync metadata, return sanitized field/index errors, and keep real HTTP proxy, tmpfs file, SSH agent, credential provider, and sandbox injection behavior out of this metadata-only layer.
- Factory secret redaction should use `RunSecretRedactor` for run records, artifact metadata/payloads, timeline events, log chunks, and error strings; prefer `Store` `WithRedactor` helpers when persisting durable factory state that may include resolved run secret output.
- Phase 22 secret broker import-boundary coverage lives in `internal/factory/secret_broker_import_boundary_test.go`; keep `TestSecretBrokerImportBoundaries` focused on production `secret*.go`, allowing standard library plus root `internal/sandbox`/`internal/verify` metadata dependencies only and forbidding command/factory orchestration, runtime adapter, provider, worker, Docker/Podman, network-client, HTTP proxy, SSH-agent, tmpfs writer, and cloud SDK dependencies.
- Local sandbox policy/secret config parsing belongs in `internal/compound/config.go` under `sandbox.networkPolicy` and `sandbox.secrets`; validate with the pure `internal/sandbox` policy validator and factory delivery-mode validator, preserve nil optional fields when absent, and keep `SaveSandboxConfig` round-tripping these metadata-only fields without provider/network calls.
- Existing sandbox security surfaces should project optional effective network policy metadata additively: deep-copy `SandboxNetworkSecurity.policyResult` through command/target clones, expose it as `networkPolicyResult` on runtime summaries and `policyResult` on factory security metadata/timeline maps, and keep secret metadata limited to requested/active delivery mode identifiers.
- Phase 22 policy/secret verification docs live in `docs/design/sandbox-runtime-v2-phase22-policy-secret-broker-verification.md` and are guarded by `cmd/phase22_policy_secret_docs_test.go`; keep the required focused commands, fake-only scope, and non-goals in sync with policy and broker contract behavior.
- Phase 22 fake-only verification guard coverage lives in `cmd/phase22_policy_secret_docs_test.go` as `TestPhase22PolicySecretFakeOnlyVerification`; keep it focused on documented `go test` commands and Phase 22 default test files, and avoid exact live-integration env literals in guard source when older broad substring guards would misclassify the test itself as an integration hook.

## Patterns from phase21-workspace-syncout-apply (2026-07-01)

- Sync-out workspace contracts belong in `internal/sandboxworkspace` as data-only, command-agnostic types; keep them free of command, factory, provider, worker, concrete runtime adapter, Cobra, and network-only imports, and represent artifacts with safe IDs, display names, relative/store paths, warning codes, recovery status, and explicit apply eligibility reasons.
- Sync-out import-boundary guard coverage lives in `internal/sandboxworkspace/sync_out_import_boundary_test.go`; keep `TestSyncOutImportBoundaries` focused on production `sync_out*.go` contract files, with only standard library imports plus root `internal/sandbox` and `internal/sandboxruntime` data contracts allowed.
- Sync-out summary construction from non-factory execution artifacts lives in `internal/sandboxexecution`; keep `BuildSyncOutSummaryFromArtifacts` pure/fake-only over safe manifest `ArtifactMetadata`, allow only the root `internal/sandboxworkspace` data-contract import, and avoid runtime, filesystem, worker, provider, command, or network dependencies.
- Safe host apply primitives belong in `internal/sandboxworkspace`; keep `SafeApply` behind the narrow `SafeApplyGit` boundary, run patch or bundle dry-run validation before mutation, and return structured handoff/warning metadata without raw project dirs, payload paths, endpoints, credentials, or secret-bearing repository URLs.
- Safe host apply must check host worktree cleanliness through `SafeApplyGit` before dry-run or mutation; dirty worktrees should return `dirty_worktree` handoff metadata with only staged/unstaged/untracked categories and no file paths.
- Safe host apply must acquire workspace locks before worktree clean checks, dry-run validation, or mutation; keep the default lock directory outside the Git worktree so lock files do not make `git status` dirty, and convert lock acquisition failures into redaction-safe `workspace_lock_failed` handoff warnings.
- Non-factory sync-out apply wiring belongs in `cmd` behind the injectable `sandboxSyncOutApplier` boundary; invoke it only after core/recovery/generated/output artifact metadata has been persisted into `sandboxexecution.Store`, and before lease release/final manifest save, so host dry-run or mutation sees durable recovery metadata.
- Default non-factory `hal run --sandbox` and `hal auto --sandbox` must leave `sandboxSyncOutApplier` nil until an explicit sync-out/apply option is selected; default manifests should keep only existing artifact metadata and omit sync-out/apply fields.
- Explicit non-factory sync-out/apply CLI flags are `--sandbox-sync-out` and `--sandbox-apply`; keep them scoped to local `hal run --sandbox` and `hal auto --sandbox`, require `--sandbox`, omit them from remote command builders, gate `sandboxSyncOutApplier` on explicit request intent, and do not add them to factory commands in this phase.
- Command-layer sync-out apply must select only explicit eligible patch or bundle artifacts before mutation, resolve their payloads through `sandboxexecution.Store.ResolveStoredPath`, and pass no payload for untracked, recovery, core, warning-only, or otherwise ineligible outputs so they become handoff results.
- Non-factory sync-out handoff guidance is attached in `cmd` after the applier returns as optional `sandboxworkspace.SafeApplyResult.HandoffInstructions`; keep references limited to safe artifact IDs, display names, and relative display paths, leaving manifest/JSON surfacing additive and explicit.
- Explicit non-factory sync-out/apply JSON output should capture remote run/auto JSON only when sync-out is requested, persist `sandboxexecution.Manifest.SyncOut`/`SyncOutApply` first, then merge those optional fields into the single stdout JSON document; default sandbox JSON pass-through must remain unchanged.
- Sync-out/apply redaction belongs on the shared `internal/sandboxworkspace` contract helpers; run `SyncOutSummary` and `SafeApplyResult` through those sanitizers before persisting manifests or augmenting JSON output.
- Phase 21 sync-out/apply verification docs live in `docs/design/sandbox-runtime-v2-phase21-workspace-syncout-apply-verification.md` and are guarded by `cmd/sandbox_sync_out_verification_test.go`; keep focused commands, additive contract checks, and fake-only non-goals in sync when this area changes.

## Patterns from phase20-lease-aware-scheduler (2026-07-01)

- Lease-aware scheduler contracts belong in `internal/sandboxtarget` as additive, command-agnostic data types; keep `SchedulerRequest`/`SchedulerResult` free of Cobra, command packages, worker clients, concrete runtime adapters, provider calls, and live inspection, and represent selection identity, capacity decisions, lease requirements, and rejection reasons separately from later scheduling behavior.
- Safe lease audit metadata belongs on `sandbox.SandboxLeaseRef` and factory's `SandboxLeaseMetadata` as redaction-safe identifiers only; command persistence should use `sandboxLeaseRefFromState` to enrich host/runtime identity, preserve acquisition/expiry times, and omit lease holders, endpoints, hostnames, filesystem paths, repository URLs, and credentials.
- Cached scheduler candidate enumeration belongs in `internal/sandboxtarget` behind `CachedState.ListHosts`; keep it fake-only and durable-metadata-only, clone returned `SandboxHost` metadata, use endpoint-safe scheduler rejections for missing/list failures, and preserve host name then ID ordering as the base ordering before later filters and ranking.
- Scheduler runtime/isolation filtering should stay in `internal/sandboxtarget`, match requested runtimes only against durable cached `SandboxHost.SupportedRuntimes`, use shared durable isolation constants plus the existing runtime category mapping, and treat explicit runtime `IsolationLevel` metadata as authoritative so stronger requested isolation is never downgraded.
- Scheduler health filtering should run in `internal/sandboxtarget` immediately after cached candidate enumeration and before runtime/isolation filtering; treat missing, empty, healthy, and unknown health as eligible, reject explicit unhealthy hosts with `FailureReasonHostUnhealthy`, and keep health rejection text sanitized to host IDs plus safe status tokens only.
- Explicit scheduler host filtering should run immediately after cached candidate enumeration and before health, runtime/isolation, and capacity filtering; a requested host must narrow the candidate set to that host or return endpoint-safe `host_not_found`/`ambiguous_target`/unsupported/capacity rejections instead of selecting another eligible host.
- Scheduler capacity filtering should stay in `internal/sandboxtarget` after health and runtime/isolation filtering; count only active non-expired `host:<hostID>` leases from injectable `CachedState.ListLeases` using `CachedState.Now`, require usable `HostCapacity.MaxConcurrentSandboxes`, and reject missing/zero capacity as conservative `capacity_unavailable`.
- Scheduler ranking should stay in `internal/sandboxtarget` after capacity evaluation; evaluate all known-capacity candidates before selecting, rank by allowed capacity, available slots, cached readiness, active lease count, max capacity, then safe host/runtime identity, and avoid map iteration, live metadata, random values, or wall-clock time outside `CachedState.Now`.
- Default run/auto/factory sandbox execution without `--sandbox-host` or `--sandbox-runtime` must stay on the legacy resolver path, avoid scheduler host enumeration and worker runtime routing, normalize worker-backed cached targets to SSH-machine compatibility, and clear stale scheduler lease refs before command records are persisted.
- Explicit run/auto/factory scheduler wiring belongs in `cmd` through the shared command-layer scheduler/lease helpers: call `sandboxtarget.Schedule` before runtime/provider construction, use injectable cached host/lease dependencies and clocks, acquire leases at the command boundary, and attach only safe `SandboxLeaseRef` metadata before manifest/record persistence.
- Scheduled run/auto/factory lease lifecycle handling belongs in `cmd` through `sandboxCommandLeaseReleaseTracker`; release acquired leases exactly once after command ownership is reached, join release failures into the command error path, and expire stale active durable leases in the default command lease lister before scheduling.
- Phase 20 scheduler guard coverage should stay fake-only: `internal/sandboxtarget` import guards explicitly forbid command, worker, execution/workspace, concrete runtime, provider, and network-only dependencies; command safety tests should lock endpoint/path/credential-safe scheduler rejections and stable lease operation errors that unwrap their original causes.
- Factory scheduler rejections happen during `sandboxexec.PhaseResolveTarget` before target-ready persistence hooks run; record endpoint-safe `resolve_target` failures at the factory command boundary without constructing providers, worker clients, or runtime drivers.

## Patterns from phase19-rootless-worker-e2e-hardening (2026-07-01)

- Explicit worker-backed rootless SandboxState persistence belongs in command target-ready hooks through an injectable `persistSandboxState` dependency; persist a sanitized clone with worker host identity only (ID, Name, Kind), exact runtime metadata, and workspace mode/input/branch/syncRef while omitting raw worker endpoints, hostnames, temp paths, bundle paths, and credential-bearing repository URLs.
- Explicit worker-backed rootless run manifests should sanitize command-owned metadata before saving: keep exact runtime and workerRouting metadata, keep workspace mode/input/branch/syncRef while omitting repository URLs, and store worker host identity plus safe security summaries without raw endpoints, supported-runtime registry details, temp paths, or credentials.
- Explicit worker-backed rootless auto manifests should use the same command-layer sanitization as run manifests: persist `Purpose=auto`, exact runtime and workerRouting metadata, workspace mode/input/branch/syncRef without repository URLs, and worker host identity plus safe security summaries without raw endpoints or supported-runtime registry details.
- Explicit worker-backed rootless factory sandbox metadata should be built in the target-ready command hook from the selected target plus `factorySandboxWorkspaceStateFromRecord`; persist exact runtime and workerRouting metadata while taking workspace mode/input/branch/syncRef from the factory run record and omitting raw endpoints, host temp paths, remote temp paths, bundle paths, credentials, and credential-bearing URLs.
- Default `hal auto --sandbox` must normalize cached worker-backed targets back to SSH-machine-compatible metadata unless `--sandbox-host` or `--sandbox-runtime` explicitly selects worker routing; strip worker runtime IDs/images, avoid worker host listing/client construction, and persist `sandboxexecution.Manifest.WorkerRouting` as nil.
- Default `hal factory run --sandbox` must normalize cached worker-backed targets back to SSH-machine-compatible metadata unless `--sandbox-host` or `--sandbox-runtime` explicitly selects worker routing; strip worker runtime IDs/images, avoid worker host listing/client construction, and persist `factory.RunRecord.Sandbox.WorkerRouting` as nil.
- Command-package worker client driver construction must stay centralized in `cmd/sandbox_worker_runtime.go`; guard tests should scan `cmd/*.go` including tests for direct `sandboxworker.NewClientDriver` calls while execution files keep routing through `sandboxWorkerRuntimeDriverFromTarget` and avoid importing `internal/sandboxworker`.
- Fake worker rootless E2E coverage should live in `internal/sandboxworker` and route a fake `sandboxruntime.Driver` through the real `Service`, Unix socket `Server`, `Client`, and `ClientDriver`; use short `/tmp` socket paths and keep default tests free of Podman, providers, external daemons, and network dependencies.
- `hal sandboxd` rootless Podman registration must check availability through the injectable command-layer availability dependency before constructing the driver, worker service, or server; unavailable Podman should return a sanitized `runtime_unavailable` classification while startup JSON lists only successfully registered drivers.
- Rootless Podman worker capability metadata belongs in `internal/sandboxworker` service descriptors: advertise exact create/start/stop/delete/inspect/exec/copy_in/copy_out operations, `HostKind=local`, `IsolationLevel=container`, and enforced security `NetworkPolicy=best_effort`, `NetworkEnforcement=none`, and `CredentialProxyMode=false` without microVM, firewall/proxy, credential proxy, or secret broker claims.
- Worker rootless lifecycle error classifications belong on shared `internal/sandboxworker` error types: client/transport failures classify as `worker_client_failed`, lifecycle `driver_error` protocol failures classify as `worker_lifecycle_failed`, and lifecycle `driver_not_found` protocol failures classify as `runtime_unavailable`; command tests should verify human/JSON propagation plus redaction instead of reclassifying at command call sites.
- Worker rootless create/start failure recovery metadata should keep target metadata on the failure path without durable registry writes: command target provisioning errors may carry a partial `PhaseProvisionTarget.Target`, `sandboxexec` start failures should merge a non-nil returned runtime target before wrapping, and factory failure records should include safe `workerRouting` for worker/rootless targets.
- `sandboxworker.ClientDriver` should return sanitized primary errors with the worker operation label (`exec`, `copy_in`, `copy_out`) and stay free of artifact/recovery warning ownership; command-owned run/auto/factory boundaries record recovery warnings and timeline events.
- Non-factory run/auto post-command artifact `CopyOut` failures should cross from `internal/sandboxexecution` as `ArtifactCollectionError` values and be converted in `cmd` into sanitized `ArtifactMetadata.Warnings` only, without partial entries; factory sandbox artifact copy failures should append sanitized `factory.EventTypeArtifactSync` timeline events at the command boundary.
- Factory sandbox command output summaries should be populated only from `sandboxexec.EventCommandOutput` through `factorySandboxTimelineWriter`; preparation/auth/input-copy output should stream through `newFactorySandboxRemoteUserOutputWriter` so visible setup output does not become `factory.EventTypeCommandOutputSummary` events or remote log chunks.
- `sandboxworker.ClientDriver.CopyOut` failure coverage should assert both no new destination file is left behind and pre-existing destination content survives; the adapter writes through a temp file in the destination directory and only renames after payload validation succeeds.
- Local rootless worker operation docs should live under `docs/design/` and be guarded by `cmd` documentation tests; keep the guide explicit opt-in, local/dev lower-isolation only, and include start/register/run/auto/factory/cleanup/integration-env details without claiming microVM isolation, scheduling, network/proxy/firewall enforcement, or secret broker support.
- Default fake-only sandbox safety guards live in `cmd/sandbox_default_fake_only_guard_test.go`; untagged default tests must not require real Podman, worker integration env vars, production sandboxd deps, or non-test worker sockets, and run/auto/factory help should show worker/rootless routing as explicit target selection.
- Sandbox runtime import-boundary coverage should stay package-local for `internal/sandboxexec`, `internal/sandboxworker`, and `internal/sandboxruntime/rootlesspodman`, with the Phase 19 `cmd` guard ensuring focused verification includes the rootless Podman subpackage and forbids command, planning, worker-record, concrete runtime, and provider leakage.

## Patterns from phase18-worker-backed-sandbox-execution-routing (2026-07-01)

- Worker-backed execution route metadata uses the shared data-only `internal/sandbox.WorkerRoutingMetadata` contract and is attached additively as optional `workerRouting,omitempty` on both non-factory `sandboxexecution.Manifest` records and factory `factory.SandboxMetadata`; keep it limited to selected worker host identity, runtime driver, isolation, and safe endpoint summaries without raw endpoints or filesystem paths.
- Worker-backed runtime driver construction belongs in `cmd/sandbox_worker_runtime.go`: pass the already-selected `sandboxruntime.Target` plus durable `sandbox.SandboxHost`, validate worker kind, requested runtime, and local Unix endpoint, then construct `sandboxworker.ClientDriver` only through injectable worker client/runtime-driver factories.
- Worker-backed routing regression guards should combine fake-only run/auto/factory behavior tests with source-level checks that execution commands keep their `sandboxWorkerRuntimeDriverFromTarget` hooks and that concrete `sandboxworker.NewClientDriver` construction remains centralized in `cmd/sandbox_worker_runtime.go`.
- Run/auto/factory worker-backed execution wiring should capture the selected `sandbox.SandboxState` in the command layer before `sandboxexec.Run` driver resolution, because `sandboxexec.ResolveDriver` receives only the command-agnostic `sandboxruntime.Target`; use the captured durable host metadata when calling the shared worker runtime resolver.
- Auto sandbox worker-backed regression tests can use a git-bundle workspace to exercise the selected runtime driver, but `executeAutoSandbox` still resolves a provider for input/report preparation; inject a fake provider and make the legacy runtime resolver fatal when asserting explicit worker-backed routing.
- Factory sandbox worker-backed regression tests still need fake provider-side bootstrap/auth/input and remote verification dependencies around the selected runtime driver; stub `bootstrap`, `runProviderScript`, `runProviderExecWithEnv`, and empty `sandboxRequests` while making the legacy runtime resolver fatal.
- Worker client construction, connection, and protocol failures should cross command boundaries as sanitized `sandboxworker.ClientError`/`ClientDriverError` values; extend `internal/sandboxworker`'s shared protocol-detail sanitizer for endpoint URL/hostname/path/secret leaks instead of redacting at individual command call sites.
- Unconstrained run/auto/factory sandbox execution must preserve legacy SSH-machine-compatible target/runtime resolution: do not list cached worker hosts, require worker endpoints, attach worker runtime IDs, or construct worker clients unless `--sandbox-host` or `--sandbox-runtime` selected a worker-backed route.
- Explicit worker-host sandbox execution supports only the rootless Podman worker-backed route for now; reject selected worker runtimes such as `microvm` in `cmd` with a `runtime_unsupported` classification before provisioning, worker-client construction, or SSH-machine fallback, and keep JSON/human errors endpoint-safe.
- Explicit rootless Podman worker-backed execution must validate the durable worker endpoint in `cmd` before provisioning, runtime-driver resolution, or worker-client construction; use the shared worker endpoint validator so errors use `worker_endpoint_invalid` plus safe endpoint summaries such as `none`, `local Unix socket`, or `<scheme> endpoint`.
- Worker-backed run/auto output streaming should stay on the existing `sandboxexec.EventCommandOutput` path: command-output summaries are populated only from remote command events, while preparation output should be routed through setup writers and excluded from persisted stdout/stderr summary artifacts.
- Worker-backed run/auto copy semantics should stay on existing runtime-driver boundaries: workspace materialization delegates to `sandboxexec.MaterializeBundleWorkspace` for runtime `CopyIn` and apply `Exec`, while non-factory core/recovery/reports artifact collection uses the selected runtime driver's `CopyOut`; command regression tests can wrap `materializeWorkspace` only to inject fake `LocalGit` and should assert manifests omit host-local bundle paths.
- Worker-backed failed run/auto recovery should stay on the existing `sandboxexec.PhaseRun` best-effort path: call `CollectRecoveryArtifactsBestEffort` with the selected worker runtime driver, keep the original command error primary, and persist recovery partial/warning metadata without raw endpoint or temp path details.
- Worker-backed security metadata should come from durable `sandbox.SandboxHost.Security` for selected worker/rootless targets inside `sandboxexec`; do not re-evaluate those targets through SSH-machine compatibility security, and keep `workerRouting` population gated by explicit `--sandbox-host`/`--sandbox-runtime` selection.
- Real worker-backed rootless Podman coverage belongs behind the explicit `worker_integration` build tag and must skip unless `HAL_WORKER_INTEGRATION_ENDPOINT`, `HAL_WORKER_INTEGRATION_HOST_NAME`, `HAL_WORKER_INTEGRATION_RUNTIME_DRIVER=rootless_podman`, and `HAL_WORKER_INTEGRATION_IMAGE` are set; default tests must not start workers, invoke Podman, or require provider credentials.
- Phase 18 worker-backed execution verification docs live under `docs/design/`, should list exact fake-only resolver/default/error/output/copy/recovery/security/contract/import-boundary commands plus explicit non-goals, and are guarded by `cmd` documentation tests to prevent review guidance drift.

## Patterns from phase17-target-selection (2026-07-01)

- Target-selection code lives in `internal/sandboxtarget`; keep it command-agnostic and limited to standard-library imports plus root `internal/sandbox` durable metadata and root `internal/sandboxruntime` contracts. Do not import Cobra, `cmd`, factory, engine, loop, PRD, compound, or concrete runtime adapter subpackages there.
- Target-selection contracts should remain data-only: `sandboxtarget.Request` carries purpose, sandbox, host, runtime, isolation, project, and fallback intent, while zero-value fallback policy preserves legacy default-running-sandbox and branch-provisioning behavior until callers opt into stricter handling.
- `sandboxtarget.Select` validates explicit cached target constraints before legacy fallback: requested hosts are matched through fakeable `CachedState.ListHosts`, missing/duplicate/unhealthy/unsupported-runtime hosts fail with endpoint-safe messages, and host-constrained requests avoid unrelated default-running sandbox selection.
- Runtime-constrained target selection without an explicit host scans fakeable cached hosts in deterministic name-then-ID order, matches only durable `SupportedRuntimes`, skips missing runtime metadata, and avoids default-running sandbox fallback when the requested runtime cannot be satisfied.
- Isolation-constrained target selection uses durable `sandbox` isolation constants plus selector-local runtime category mapping (`ssh_machine` -> `host`, `rootless_podman` -> `container`, `microvm` -> `vm`); persisted sandbox runtime `IsolationLevel` is authoritative when present so stronger requests fail instead of being downgraded.
- Unconstrained `sandboxtarget.Select` preserves legacy resolution through fakeable `CachedState` callbacks: explicit sandbox load first, exactly one running sandbox as the default fallback, and `ProvisioningPlan` for command-layer create paths; use `RuntimeForSandbox` to keep missing runtime metadata on SSH-machine compatibility.
- When `sandboxtarget.Select` attaches selected metadata to a returned `sandbox.SandboxState`, copy cached `SandboxHost` records before assignment and merge requested runtime driver/isolation constraints into existing durable runtime metadata so runtime ID, image, and worker ID are preserved.
- Runtime driver resolution in `cmd/sandbox_runtime_compat.go` must consume the already-selected `sandboxruntime.Target` only: keep default run/auto/factory execution limited to missing/SSH-machine compatibility or explicit `rootless_podman`, and fail unsupported explicit drivers such as `microvm` or worker-only driver strings instead of scanning hosts or downgrading.
- Target-selection CLI flags belong in `cmd` on sandbox-capable entrypoints only: `--sandbox-host` and `--sandbox-runtime` parse into host-side request fields, validate runtime values through root `sandboxruntime` constants, keep help text scoped to cached target selection, and stay out of remote `hal run`/`hal auto` command builders.
- Default sandbox execution regression tests in `cmd` should stay fake-only: inject fake default target resolvers, fake runtime drivers, temporary `HAL_CONFIG_HOME`, and deterministic clocks where records are saved, and assert default run/auto/factory paths do not explicit-load, provision, live-refresh workers, or construct concrete adapters.
- Phase-specific target-selection verification docs should live under `docs/design/`, list exact focused Go/doc/build commands plus explicit fake-only non-goals, and be guarded by a `cmd` documentation test so review guidance does not drift.

## Patterns from phase16-runtime-inspection (2026-07-01)

- Runtime inspection JSON contracts should define command-layer constants and response structs in `cmd`, document safe endpoint summaries and explicit sparse values under `docs/contracts/`, and lock referenced example files with strict decoding plus deterministic runtime ID ordering tests before command implementation stories use them.
- Runtime status JSON error examples should retain the full endpoint-safe response shape, including safe host/runtime identity, source metadata, capacity/readiness/security placeholders, diagnostics/errors arrays, and stable error codes such as `runtime_not_found`.
- Cached runtime list command implementations should load durable `internal/sandbox.SandboxHost` records through injectable command-layer dependencies, derive runtimes/capacity/security only from cached host metadata, emit exactly one `sandbox-runtime-list-v1` JSON document in JSON mode, and keep worker-client factories unused unless an explicit live path requests them.
- Cached runtime status command implementations should load durable `internal/sandbox.SandboxHost` records through injectable command-layer dependencies, match the requested runtime only against durable `SupportedRuntimes`, emit `sandbox-runtime-status-v1` success/error documents from shared response structs, and keep human missing-host/runtime errors limited to the requested identity.
- Live runtime list command implementations should load the durable host first, require worker kind plus a local Unix socket endpoint before constructing clients, query fakeable worker status/capabilities for response-only `live-refreshed` metadata, wrap client failures in sanitized `sandboxworker.ClientError`, and avoid persisting refreshed runtime data.
- Live runtime status command implementations should load the durable host first, require worker kind plus a local Unix socket endpoint before constructing clients, use live worker capabilities as the authority for the requested runtime, emit response-only `sandbox-runtime-status-v1` live metadata, wrap client failures in sanitized `sandboxworker.ClientError`, and avoid persisting refreshed runtime data.
- Non-worker `hal sandbox runtime list --live` requests should not error or construct worker clients; render cached durable metadata through the `sandbox-runtime-list-v1` `unsupported-live` source mode with endpoint-safe diagnostics.
- Runtime inspection endpoint summaries should classify both `unix:` endpoints and raw absolute Unix socket paths as `local Unix socket`; command safety tests should cover human and JSON cached, live, unsupported-live, and error paths without raw endpoint leaks or unsupported enforced-security claims.
- Runtime inspection regression guards should keep `hal sandbox runtime` scoped away from `hal sandboxd`, `hal run --sandbox`, `hal auto --sandbox`, and `hal factory run --sandbox` by checking command metadata, existing execution flags, absence of runtime inspection flags such as `--live`, and absence of runtime subcommands without invoking daemon or sandbox execution paths.
- Phase-specific runtime inspection verification docs should live under `docs/design/`, list exact focused Go/doc/build commands plus explicit integration non-goals, and be guarded by a `cmd` documentation test so review guidance does not drift.

## Patterns from phase15-worker-hosts (2026-07-01)

- New user-facing Cobra command scaffolds should provide `Use`, `Short`, `Long`, and `Example` for every in-scope group and leaf command; `cmd` metadata tests walk the global command tree and family examples should contain the full command path.
- After adding or changing Cobra command surfaces, run `make docs-cli` and `make docs-check`; phase-specific verification docs should be locked with focused doc guard tests so generated CLI docs, contract docs, and verification commands do not drift.
- Prefer `newXCommand(deps)` constructors for new command families so command registration/help tests can use fake dependencies without sockets, providers, daemons, network access, or real runtime adapters.
- Worker host durable mapping belongs in `cmd`: convert `internal/sandboxworker` status/capability payloads into `internal/sandbox.SandboxHost` there, keep offline records conservative, and persist security only as requested/enforced durable summaries so `internal/sandboxworker` stays command-agnostic.
- Offline worker host registration should reuse the command-layer worker metadata mapper and persist through `internal/sandbox.SaveHost`; command tests should isolate the global registry with temporary `HAL_CONFIG_HOME` and human output should summarize local Unix socket endpoints without printing raw socket paths.
- Live worker host command paths should keep worker access behind fakeable command-layer client factories plus injectable clocks; query worker status/capabilities before persistence, wrap client failures in sanitized `sandboxworker.ClientError`, and do not write durable records when live refresh fails.
- Human worker host list output should read durable records through `internal/sandbox.ListHosts`, rely on its name-then-ID ordering, and render endpoint summaries such as `local Unix socket` or `<scheme> endpoint` instead of raw socket paths, hosts, or credential-bearing URLs.
- Worker host list JSON should use the dedicated `sandbox-host-list-v1` contract, emit exactly one JSON document, preserve `internal/sandbox.ListHosts` ordering, and expose endpoint summaries only rather than raw socket paths, hostnames, credentials, or URL query strings.
- Cached worker host status output should read a single durable record through `internal/sandbox.LoadHost`, avoid worker client calls unless an explicit live path requests them, label human output as cached/not live, and reuse safe endpoint/runtime/capacity summaries instead of raw socket paths, hosts, or credential-bearing URLs.
- Live worker host status refresh should load the durable host first, require a local Unix socket endpoint, reuse the command-layer worker metadata mapper, preserve durable identity/endpoint/labels, and persist successful refreshes with `internal/sandbox.ForceWriteHost`.
- Worker host status JSON should use the dedicated `sandbox-host-status-v1` contract, identify `cached` vs `live-refreshed` source metadata, emit exactly one JSON document, and reuse safe endpoint/runtime/capacity summaries instead of raw socket paths, hostnames, credentials, or URL query strings.
- Worker host deletion is registry-only: use `internal/sandbox.RemoveHost`, avoid worker client calls and runtime target mutation, and make human output explicit that only the durable record was removed.

## Patterns from phase14-worker-io (2026-07-01)

- Worker I/O limit constants and shared validation helpers live in `internal/sandboxworker/io_validation.go`; keep exec/copy payload bounds command-agnostic, reject unbounded reads before dispatch, and route validation details through `sanitizeProtocolErrorDetail` so host paths and secrets do not enter protocol errors.
- Worker exec protocol schema lives in `internal/sandboxworker/exec.go`; require `operationId`, target metadata, non-empty argv, explicit stdout/stderr capture limits, and `sizeBytes` that matches bounded stdin/stdout/stderr payload data.
- Worker exec service routing lives in `internal/sandboxworker/exec_service.go`; route through `DriverRegistry` to `sandboxruntime.Driver.Exec`, capture stdout/stderr with bounded writers, keep command errors with an `ExecResult` in `ExecResponse.Error`, and reserve top-level protocol errors for lookup, unsupported, context, or no-result failures.
- Worker copy protocol schema lives in `internal/sandboxworker/copy.go`; keep copy-in/copy-out payloads command-agnostic, encode file content as bounded base64 JSON payloads, and validate `sizeBytes` against decoded bytes before service dispatch.
- Worker copy service routing lives in `internal/sandboxworker/copy_service.go`; stage base64 copy-in/copy-out payloads through temporary files, route through `DriverRegistry` to `sandboxruntime.Driver.CopyIn`/`CopyOut`, enforce copy-out response limits before serialization, and leave capability exposure centralized in `internal/sandboxworker/service.go`.
- Worker capability metadata lives in `internal/sandboxworker/service.go`; after exec/copy handlers exist, default top-level and runtime-driver operations include `exec`, `copy_in`, and `copy_out`, while `ServiceOptions.SupportedOperations` and `RuntimeDrivers` can intentionally publish conservative subsets for disabled/no-handler scenarios.
- Worker client I/O methods live in `internal/sandboxworker/client.go`; route exec/copy envelopes through `Client.roundTrip`, validate before transport dispatch, enforce returned payload limits against caller-requested limits, and sanitize embedded response errors before returning payloads.
- Worker safety redaction coverage belongs in `internal/sandboxworker/safety_test.go`; assert serialized protocol/adapter error responses omit credential values, host source/temp paths, and remote temp paths, and extend `sanitizeProtocolErrorDetail` rather than sanitizing at individual call sites.
- Worker `ClientDriver.Exec` forwarding lives in `internal/sandboxworker/adapter.go`; convert runtime exec requests into bounded worker exec payloads, read stdin with `io.LimitReader(MaxExecStdinBytes+1)` before dispatch, request max stdout/stderr capture limits, write returned bounded output into provided runtime writers, and surface embedded worker errors or truncation through sanitized `ClientDriverError` while returning the exit result.
- Worker `ClientDriver.CopyIn`/`CopyOut` forwarding lives in `internal/sandboxworker/adapter.go`; read copy-in sources with `io.LimitReader(MaxCopyInPayloadBytes+1)` before dispatch, send copy payloads through bounded base64 protocol fields, materialize successful copy-out payloads to the requested local destination, and avoid writing partial copy-out files when worker errors or truncation occur.
- Worker I/O local socket round-trip coverage belongs in `internal/sandboxworker/client_test.go`; use fake driver-backed `Service`/`Server` instances plus short `/tmp` socket paths, and keep the tests free of real runtime providers, network egress, or credential material.
- Default sandbox runtime resolver wiring lives in `cmd/sandbox_runtime_compat.go`; keep run/auto/factory defaults limited to SSH-machine or explicit rootless Podman metadata, keep worker-backed `sandboxworker.ClientDriver` construction opt-in only, and use fake runtime-driver factories in regression tests instead of constructing concrete adapters.
- Phase 14 worker I/O verification is intentionally focused: document the allowed commands in `docs/design/sandbox-runtime-v2-phase14-worker-io-verification.md`, lock the checklist with `internal/sandboxworker/phase14_verification_test.go`, and do not run `go test ./...` or real runtime/provider workflows for this phase.

## Patterns from phase13-sandboxd-self-hosted-worker-daemon-foundation (2026-07-01)

- Worker protocol schema types live in `internal/sandboxworker`; keep the foundational request/response/status/capability/runtime-driver/security-policy types command-agnostic, package-local to the worker boundary, and free of Cobra, `cmd`, factory, PRD, compound, loop, concrete runtime adapters, or durable command-layer records.
- `internal/sandboxworker` import-boundary tests should parse production Go imports and allow only standard-library packages plus the root `internal/sandboxruntime` contract package; keep command packages, durable sandbox state, and concrete runtime/provider adapters forbidden.
- Worker capability and security metadata must separate requested controls from enforced controls; validation should reject metadata that claims deny-by-default network enforcement, firewall/proxy enforcement, credential-proxy support, or microVM isolation for the local worker foundation.
- Worker runtime driver routing belongs behind `sandboxworker.DriverRegistry`; register concrete `sandboxruntime.Driver` adapters outside `internal/sandboxworker`, keep ID listing deterministic, and cover registry behavior with fake drivers only.
- Worker status/capability generation belongs in `sandboxworker.Service`: derive supported driver IDs from `DriverRegistry`, keep top-level supported operations conservative until handlers exist for them, and use fake drivers plus honest security metadata in tests.
- `sandboxworker.Service` is the `RequestHandler` for status/capability socket operations; valid-but-unimplemented worker operations should return structured `unsupported_operation` errors, while canceled/deadline-exceeded contexts should return structured protocol errors.
- Worker lifecycle socket operations belong in `sandboxworker.Service`: route create/start/stop/delete through `DriverRegistry`, bridge only command-agnostic `sandboxruntime` target metadata, and sanitize driver errors before returning protocol responses.
- Worker inspect socket operations belong in `sandboxworker.Service`: route inspect through `DriverRegistry`, use the worker `InspectRequest`/`Target` protocol shape, and include `inspect` in top-level supported operations only once the handler is implemented.
- Worker socket transport belongs in `sandboxworker.Server` with an injected `RequestHandler`: keep the transport limited to local Unix sockets, request validation, structured protocol errors, and context-aware shutdown while operation dispatch stays behind handler/service code.
- Worker client calls belong behind `sandboxworker.Client` and `ClientTransport`: keep local transport Unix-only, one JSON request/response per connection, context-aware, and sanitize connection/protocol error details before they cross command or persistence boundaries.
- Worker client runtime-driver adapters belong in `sandboxworker.ClientDriver`: construct them explicitly from a `RuntimeDriverClient`, forward lifecycle/inspect/exec/copy only through the worker protocol as dedicated adapter stories add support, keep not-yet-forwarded operations explicitly unsupported, and do not wire run/auto/factory defaults to worker adapters without a separate story.
- The `hal sandboxd` command should stay thin and injectable: parse flags, build `sandboxworker.DriverRegistry` with concrete adapters outside `internal/sandboxworker`, create `sandboxworker.Service`/`Server`, render startup/errors, and test with fake service/server dependencies rather than binding real sockets or invoking Podman.
- Worker safety coverage should stay fake-only and cross-cutting: assert redaction, capability gating or unsupported-operation behavior, honest capabilities/security posture, credential-free protocol responses, build-tagged optional integrations, and static guards against host Docker socket or privileged-container dependencies.
- Unix socket tests should allocate short socket paths, such as `os.MkdirTemp("/tmp", ...)`, because macOS rejects long `t.TempDir()`-derived socket paths with `bind: invalid argument`.

## Patterns from phase12-rootless-podman-local-runtime-driver-for-hal-sandbox-runtime-v2 (2026-07-01)

- Optional real Podman integration tests for the rootless runtime belong under the explicit `podman_integration` build tag; require `HAL_PODMAN_TEST_IMAGE` to name an image that already exists locally, verify it with `podman image exists`, and never run `podman pull` by default.
- Preserve the `hal sandbox list --json` `sandbox-list-v1` contract when adding Sandbox Runtime v2 metadata: required entry fields stay `id`, `name`, `provider`, `status`, and `createdAt`, and runtime/security/isolation metadata should not be added to this list surface without a contract version change.
- Human `hal sandbox status NAME` output for `rootless_podman` states must not imply VM isolation, production defaults, or production-ready security posture; keep lower-isolation/rootless claims on factory status metadata and docs where explicitly modeled.

## Patterns from phase/sandbox-runtime-v2-10-workspace-sync (2026-06-30)

- Workspace sync contracts live in `internal/sandboxworkspace/sync.go`; keep the core sync surface command-agnostic with package-local request/result/target types and narrow `LocalGit`/`RemoteClient` interfaces rather than Cobra, factory records, or concrete provider/runtime adapters.
- Materialization metadata should be generated through `NewMaterializationResult` / `BundleMaterializationFromCreateResult`; do not persist host-local bundle paths in result or manifest metadata.
- Host-side git-bundle preparation belongs in `sandboxworkspace.PrepareLocalBundle`: pass the planned `Plan` plus an execution-local `BundleDir`, keep create/verify behavior behind `LocalGit`, reject dirty plans before adapter calls, and rely on JSON-omitted `LocalPath` plus safe bundle metadata for later steps.
- `GitCLIInspector` is the concrete `LocalGit` adapter: create bundles with a positive branch/`HEAD` ref plus optional `^upstream`, verify with `git bundle verify` and `git bundle list-heads`, and route bundle command failures through sanitized errors so host paths and credentials are not serialized.
- Remote bundle copy-in belongs in `sandboxworkspace.CopyLocalBundle`: pass the planned `Plan`, verified `LocalBundleResult`, `RemoteTarget`, and sandbox destination dir, keep transfer behind `RemoteCopier.CopyIn`, and return only redaction-safe remote bundle metadata.
- Remote bundle apply belongs in `sandboxworkspace.ApplyRemoteBundle` / `BundleMaterializer`: run deterministic init-or-update, bundle fetch, and checkout commands through `RemoteCommandRunner.Exec`, and wrap apply failures as sanitized `workspace bundle apply` errors without raw remote output.
- Shared command integration for prepared git-bundle workspaces belongs in `internal/sandboxexec.MaterializeBundleWorkspace`, which adapts the resolved `sandboxruntime.Driver` through `RuntimeWorkspaceClient`; keep command packages passing metadata into this helper instead of duplicating bundle copy/apply sequencing.
- Sandbox command preflight paths that receive a valid workspace plan should populate `req.Workspace` before returning unsupported-input errors so failed execution manifests retain safe provenance metadata.
- Until the run/auto git-bundle preflight guards are intentionally removed, direct executor tests can bypass preflight with prepared `git_bundle` workspace metadata to validate the shared materialization branch.
- Keep `internal/sandboxworkspace` import-boundary tests updated when adding sync code so the package does not start importing `cmd`, `internal/factory`, `internal/prd`, `internal/compound`, `internal/loop`, Cobra, or concrete runtime adapters.

## Patterns from phase/sandbox-runtime-v2-11-recovery-artifacts (2026-06-30)

- Non-factory sandbox execution manifests keep the legacy top-level `artifacts` array stable; new collection state belongs in additive `artifactMetadata` with `collected`, `partial`, and `warnings` entries.
- For non-factory sandbox artifact metadata, `path` is a safe display path that may be a workspace path like `.hal/prd.json`, while `storedPath` must stay store-relative under the execution ID; never add host temp/source path fields to manifest metadata.
- `internal/sandboxexecution` validates artifact metadata in `validateManifestForSave`; collected entries require both display and store-relative paths, while partial/warning artifact entries require at least a safe display path.
- Use `sandboxexecution.Store.SaveArtifactFile` for collected non-factory artifact files: pass caller-facing `ArtifactMetadataEntry.Path`, let the store compute `storedPath` under `<execution-id>/artifacts/`, and keep local source paths out of returned metadata and persistence errors.
- Use `sandboxexecution.Store.SaveHandoffFile` and `SaveRecoveryFile` for non-factory handoff/recovery payloads so metadata stores safe display paths while generated `storedPath` values stay under `<execution-id>/handoff/` or `<execution-id>/recovery/`.
- Shared non-factory runtime artifact collection belongs in `internal/sandboxexecution.CollectRuntimeArtifacts`: pass a narrow `RuntimeArtifactCollector` backed by `sandboxruntime.Driver.Exec`/`CopyOut`, copy remote files to temp files first, and persist through store helpers instead of importing command, factory, or concrete runtime adapter packages.
- Keep `internal/sandboxexecution` and `internal/sandboxexec` import-boundary tests explicit about forbidden `cmd`, `internal/factory`, `internal/prd`, `internal/compound`, Cobra, and concrete adapter subpackage imports such as `internal/sandboxruntime/sshmachine`; `internal/sandboxexecution` still imports root `internal/sandbox` for manifest metadata structs.
- `RuntimeArtifactRequest.Optional` is the opt-in non-fatal path for collection: required artifacts remain the zero-value default and fail on CopyOut/store errors, while optional CopyOut/store errors append partial metadata plus sanitized warnings without remote, temp, or source paths.
- Use `sandboxexecution.CollectCoreStateArtifacts` when wiring non-factory sandbox core state collection: it copies `.hal/prd.json` and `.hal/progress.txt` for run executions, adds `.hal/auto-state.json` for auto executions, and appends metadata through `Store.AppendArtifactMetadata`.
- Use `sandboxexecution.CollectRecoveryArtifacts` when wiring non-factory generated recovery collection: it runs runtime `Exec` in the remote workspace to create `.hal/recovery/workspace.patch`, copies it out with runtime `CopyOut`, persists it via `Store.SaveRecoveryFile`, and appends recovery metadata to the manifest.
- Use `sandboxexecution.CollectReportsArchiveArtifacts` when wiring non-factory generated reports collection: it runs runtime `Exec` to create `.hal/reports.tar` from `.hal/reports` when present, copies it out with runtime `CopyOut`, persists it via `Store.SaveArtifactFile`, and records missing reports as partial metadata plus sanitized warnings.
- Use `sandboxexecution.SaveCommandOutputSummaryArtifacts` when wiring non-factory stdout/stderr summaries: pass already-sanitized summary text, persist payloads under `artifacts/output/`, and keep manifest metadata limited to safe `output/*-summary.txt` display paths plus store-relative `storedPath` values.
- Run sandbox post-execution collectors should use the resolved `sandboxruntime.Driver` captured during `executeRunSandbox`; because `saveRunSandboxManifest` rebuilds manifests from request/target state, preserve existing top-level `Artifacts` and additive `ArtifactMetadata` when saving final status.
- Auto sandbox post-execution core state collectors should use the resolved `sandboxruntime.Driver` captured during `executeAutoSandbox`; because `saveAutoSandboxManifest` rebuilds manifests from request/target state, preserve existing top-level `Artifacts` and additive `ArtifactMetadata` when saving final status.
- `hal run --sandbox` output summary capture belongs in the `sandboxexec.EventCommandOutput` handler inside `executeRunSandbox`; avoid wrapping command writers for summaries so preparation output is excluded and JSON stdout passthrough remains a single remote JSON document.
- `hal run --sandbox` generated artifact wiring belongs after core state collection and should call `CollectRecoveryArtifacts` before `CollectReportsArchiveArtifacts`; command tests that assert runtime execution order should distinguish the remote command `Exec` from recovery/reports generation `Exec` calls.
- `hal auto --sandbox` generated artifact wiring belongs after core state collection and should call `CollectRecoveryArtifacts` before `CollectReportsArchiveArtifacts`; command tests that assert runtime execution order should distinguish the remote auto command `Exec` from recovery/reports generation `Exec` calls.
- `hal auto --sandbox` output summary capture belongs in the `sandboxexec.EventCommandOutput` handler inside `executeAutoSandbox`; persist sanitized summaries after generated artifact collection with `SaveCommandOutputSummaryArtifacts` so JSON stdout passthrough remains a single remote JSON document.
- After non-factory `hal run --sandbox` or `hal auto --sandbox` remote command failures, attempt only best-effort recovery collection with `CollectRecoveryArtifactsBestEffort`; keep the original `sandboxexec.PhaseRun` error primary and record recovery generation/copyout/persist issues as artifact warnings.
- Sandbox command JSON-mode tests should decode stdout with `json.Decoder` and assert a second decode returns `io.EOF`; plain `json.Unmarshal` is less explicit about guarding against trailing warning text or double JSON documents.

## Patterns from phase/sandbox-runtime-v2-9-runtime-driver (2026-06-30)

- Runtime-driver boundary contracts live in `internal/sandboxruntime`; keep this package command-agnostic by using package-local target/request types and only standard-library dependencies.
- Runtime driver IDs are mirrored between durable sandbox metadata constants in `internal/sandbox/types.go` and runtime-boundary constants in `internal/sandboxruntime/types.go`; keep those values in sync, and keep nil/empty runtime metadata defaulting to `ssh_machine` in sandbox execution adapters.
- The root `internal/sandboxruntime` package has an import-boundary test that scans production Go files and forbids Cobra, `cmd`, `internal/factory`, `internal/prd`, `internal/compound`, and `internal/loop`; put provider/runtime adapters outside the root contracts package.
- SSH-machine runtime adapter code lives in `internal/sandboxruntime/sshmachine`; preserve legacy target resolution by deriving provider inputs through `sandbox.ConnectInfoFromState`, and wrap provider lifecycle failures in typed errors that keep operation name, driver ID, and the underlying provider error.
- Rootless Podman runtime adapter code lives in `internal/sandboxruntime/rootlesspodman`; keep its lower-isolation metadata explicit (`rootless_podman`, host kind `local`, isolation `container`) and route future lifecycle/exec/copy behavior through package-local fakeable command runner interfaces instead of command packages or direct workflow dependencies.
- Rootless Podman lifecycle commands should be constructed as non-privileged `podman` argv behind `LifecycleCommandRunner`: do not add Docker socket mounts, keep `Create` metadata at `rootless_podman`/`container`, and wrap command failures in sanitized `OperationError` values.
- Rootless Podman exec commands should construct deterministic `podman exec` argv behind `ExecCommandRunner`: use `--interactive` only when stdin is supplied, `--workdir` plus sorted `--env` flags for runtime request data, forward streams through `CommandRequest`, and wrap failures or cancellation in sanitized `OperationError` values.
- Rootless Podman file transport should construct `podman cp` argv behind `CopyCommandRunner`; keep normal unit tests fake-runner-only, avoid driver-side host file mutation, and route copy failures through sanitized `OperationError` values so host paths, Docker socket paths, and secret assignments are redacted.
- SSH-machine runtime exec should call the legacy provider `Exec` with command args unchanged, then configure the returned `*exec.Cmd` with runtime stdin/stdout/stderr/env/workdir; stderr defaults to stdout, and context cancellation errors must remain unwrap-compatible through the adapter operation error.
- SSH-machine runtime file transport should stay provider-Exec-backed: CopyIn streams the local source through stdin to a remote shell helper, CopyOut captures remote stdout into a local temp file before rename, and both wrap failures with `OperationError` operation names (`copy_in`/`copy_out`).
- `internal/sandboxexec.PrepareContext` uses `sandboxruntime.Target` and `sandboxruntime.ConnectionInfo` for preparation hooks; when command code still needs legacy provider structs, bridge at the command boundary through `cmd/sandbox_runtime_compat.go` instead of re-exposing provider types from sandboxexec preparation.
- `internal/sandboxexec.RunContext` and `Result` expose runtime primitives (`sandboxruntime.Target`, `ConnectionInfo`, `Driver`) plus cloned command snapshots; command callers that still need provider execution should resolve an SSH-machine driver with `sandboxRuntimeDriverFromProvider` and convert at `cmd/sandbox_runtime_compat.go`.
- `sandboxexec.Run` defaults to `sandboxruntime.Driver.Exec` when no command-specific `RunCommand` is supplied, forwarding command args, env, workdir, stdout, stderr, and stdin; command-specific wrappers should only override this when they need compatibility behavior such as remote working-directory shell wrapping.
- Run/auto/factory sandbox command callers should preserve the richer legacy `*sandbox.SandboxState` captured by `OnTargetReady` and use `sandboxexec.Result.Target` only as a fallback so host, runtime, and security metadata are not dropped.
- `sandboxexec.PhaseError` intentionally carries `*sandbox.SandboxState` plus `RuntimeDriver`, but not `sandbox.Provider` or `*sandbox.ConnectInfo`; command callers should use the phase-error target only as a fallback when no richer `OnTargetReady` state is available.
- Sandbox command runtime-driver resolvers that support rootless Podman should receive the full `sandboxruntime.Target` and select `rootless_podman` only from explicit `target.Runtime.Driver`; missing or `ssh_machine` metadata must keep using provider-backed SSH-machine drivers.
- `hal run --sandbox` remote command execution goes through `runSandboxDeps.resolveRuntimeDriver` and `sandboxruntime.Driver.Exec`; keep provider-backed compatibility helpers scoped to workspace bootstrap/auth sync until those preparation paths are migrated.
- `hal auto --sandbox` remote command execution goes through `autoSandboxDeps.resolveRuntimeDriver` and `sandboxruntime.Driver.Exec`; keep provider-backed compatibility helpers scoped to workspace bootstrap, auth sync, and input-copy preparation until those paths are migrated.
- Factory sandbox final remote command execution goes through `factorySandboxExecutorDeps.resolveRuntimeDriver` and `sandboxruntime.Driver.Exec`; keep provider-backed compatibility helpers scoped to workspace bootstrap, auth sync, input-copy preparation, and cleanup until those paths are migrated.
- Factory sandbox runtime-driver resolution should receive the full `sandboxruntime.Target` and use the shared `sandboxRuntimeDriverFromTarget` helper so explicit `rootless_podman` metadata selects the rootless adapter while absent or `ssh_machine` metadata preserves SSH-machine behavior.
- Factory sandbox runtime exec preserves SSH-machine working-directory compatibility by embedding `cd <remote workspace>` in the shell command from `factorySandboxRemoteCommandArgs`; do not set `sandboxruntime.ExecRequest.WorkDir` for that final remote auto command unless intentionally changing legacy behavior.

## Patterns from local-factory-queue-storage (2026-06-21)

- Factory queue storage should build on `internal/factory.Store`: keep queue state under the global config-backed factory root (`StoreDir()/queue.json`), treat a missing queue file as empty read-only state, and preserve corrupt queue files by returning parse errors without overwriting or deleting them.
- Queue read-modify-write operations should use `Store.UpdateQueue` instead of separate `LoadQueue`/`SaveQueue` calls; it holds the local `queue.lock` across load, mutation, and temp-file-plus-rename save so concurrent local workers do not lose updates.
- Queue command code should use the Store-level FIFO helpers (`EnqueueQueueEntry`, `ListQueue`, `ClaimNextQueueEntry`) and inject `QueueOperationOptions` in tests; FIFO order is by `CreatedAt` with `QueueID` as the stable tie-break.
- Queue lifecycle transitions should use Store-level helpers (`ClaimNextQueueEntry`, `MarkQueueEntrySucceeded`, `MarkQueueEntryFailed`) so claim metadata, attempt counts, terminal timestamps, and retained history stay consistent.
- Queue command implementations should validate executor modes through `factory.ValidateExecutorMode`, enqueue through Store helpers, and record queue-related run/timeline state in `cmd` so queue state and factory run history stay synchronized.
- `hal factory queue work` should claim via `Store.ClaimNextQueueEntry`, record the queue claim event in `cmd`, execute the run through the shared factory run lifecycle helper, and finalize the queue entry with `MarkQueueEntrySucceeded`/`MarkQueueEntryFailed`.
- Queue worker command tests should inject `runPipeline`; no-work tests should fail if the executor is called so empty queue processing never depends on Codex, GitHub, sandbox providers, or other external execution.
- Factory queue command definitions live in `cmd/factory_queue.go`; wire them from `cmd/factory.go`, update factory command metadata/link tests in `cmd/factory_test.go`, and regenerate `docs/cli` with `make docs-cli`.

## Patterns from hal/factory-remote-workspace-bootstrap (2026-06-21)

- Factory bootstrap command execution belongs behind `internal/factory.BootstrapCommandExecutor`; use `RunBootstrapStep` with injected fake executors and deterministic clocks in tests instead of spawning git, Hal, or engine CLIs directly.
- Tooling verification bootstrap belongs in `internal/factory.BootstrapVerifyTooling`; configure Hal and engine checks with `BootstrapToolingCheck`, and use `InstallCommand` only with `BootstrapOptions.InstallMissingCLIs` so missing executables classify as `dependency` while failed setup commands classify as `engine_setup`.
- Repository checkout bootstrap belongs in `internal/factory.BootstrapRepositoryCheckout`; inject `RepoExists`, executor, and clock dependencies so tests assert deterministic git clone/fetch/checkout commands without touching real repositories.
- Run branch preparation also belongs in `BootstrapRepositoryCheckout` after base checkout; inject `LocalBranchExists`/`RemoteBranchExists` probes so tests can cover local retry, remote resume, and first-run branch creation without real git refs.
- Hal template, standards, managed skill, and engine-link setup belongs in `internal/factory.BootstrapRefreshHal`; run `hal init`/`hal init --refresh-templates` and `hal links refresh` through the executor boundary instead of duplicating template or skill install logic.
- Bootstrap request environment values belong on `BootstrapRequest.Env` and flow through `BootstrapStepDeps.Request`; call `RunBootstrapStep` so env injection, command-summary sanitization, and command-result sanitization stay centralized.
- Bootstrap command/timeline persistence should use `NewBootstrapSanitizer` or `SanitizeBootstrapCommand*` helpers so sensitive env key names and configured secret values are redacted before serialization.
- Bootstrap callers should record step outcomes through `recordBootstrapStepResult` / `BootstrapTimelineEventFromStep` so `BootstrapResult.Steps` and `BootstrapResult.Timeline` stay one-to-one with sanitized command summaries, output metadata, and failure category metadata.
- High-level remote workspace setup should enter through `internal/factory.BootstrapWorkspace` with one `BootstrapDeps` value; it composes repository checkout, tooling verification, Hal refresh, and final checks while preserving shared executor, clock, branch probes, env injection, and first-failure stop behavior.

## Patterns from hal/factory-sandbox-executor (2026-06-21)

- Sandbox-backed factory execution side effects belong behind `factorySandboxExecutorDeps` in `cmd/factory_sandbox_executor.go`; extend the normalized dependency struct for registry, provisioning/start, provider exec, clock, and store persistence behavior so tests can fake each boundary without real sandbox providers or remote commands.
- `hal factory run --sandbox` selection belongs in `factoryRunRequest.Sandbox` and dispatches through `factoryRunDeps.runSandbox`; keep the no-flag path on `runPipeline` and cover both paths with injected-dependency tests.
- Existing sandbox reuse in `runFactorySandboxExecutorWithDeps` should persist `RunRecord.SandboxName` plus `RunRecord.Sandbox` immediately after target resolution/start, and no-name resolution should preserve `sandbox.ResolveDefault` running-only error strings unless provisioning behavior explicitly handles them.
- Sandbox provision/start failures should be persisted inside `runFactorySandboxExecutorWithDeps` with `RunStatusFailed`, `FailureCategoryPipeline`, and sandbox handoff metadata before returning the wrapped error to the outer factory runner.
- Sandbox remote execution should pass a structured `factoryRunAutoRequest` through `factorySandboxExecutorRequest`; build exact provider args with `factorySandboxRemoteAutoArgs` at the sandbox executor boundary and avoid env/config pass-through unless a redaction-safe contract explicitly requires it.
- Sandbox remote output timeline capture belongs at the sandbox executor boundary: wrap the provider exec writer, tee to user output, split complete lines, sanitize with the sandbox redactor, and persist `command_output_summary` events tagged with `source=remote_sandbox`.
- Sandbox executor remote lifecycle events should be appended through `factorySandboxTimelineWriter` so start/output/completion events share one sequence counter and consistent `source=remote_sandbox` metadata before the outer factory runner records terminal success/failure.
- Sandbox remote execution failures should be sanitized and saved inside `runFactorySandboxExecutorWithDeps` before returning to the outer factory runner; `markFactoryRunFailed` should preserve existing sandbox SSH handoff commands while the status inspection command remains available through `nextAction`.
- Factory sandbox status metadata is sourced from `factorySandboxMetadataFromState`; when copying Sandbox Runtime v2 state into `factory.SandboxMetadata`, keep only safe host/runtime/workspace/security/lease summaries, omit raw repo paths and lease holders, and normalize `rootless_podman` isolation to `container`.

## Patterns from hal/rename-to-hal (2026-02-04)

- For runtime directory renames, use template.HalDir in Go code but separately sweep hardcoded user-facing strings in cmd/* and prompt templates (e.g., config.go, explode.go) so paths like .hal stay consistent.
- Skill renames should use git mv for internal/skills directories, then update embed.go (//go:embed path, SkillContent keys, SkillNames) and adjust .gitignore to `/hal` so the binary is ignored without hiding skills/hal.
- Migration logic in cmd/init.go follows a safe existence-check flow: if legacy .goralph exists and .hal does not, rename; if both exist, warn and continue with .hal.
- Rename passes must include branch-prefix literals and test fixtures (e.g., ralph/ -> hal/) because they are not covered by import or constant changes.

## Patterns from compound/init-migration-tests (2026-02-04)

- To test Cobra RunE handlers, extract testable logic into standalone functions that accept an `io.Writer` for output capture (e.g., `migrateConfigDir(oldDir, newDir string, w io.Writer)`), then test the function directly with `bytes.Buffer`.
- To force `os.Rename` failure in tests, use `os.Chmod(dir, 0555)` on the parent directory to deny write permission; remember to restore with `t.Cleanup` so `t.TempDir()` cleanup succeeds.
- Migration logic in cmd/init.go is now in `migrateConfigDir` function with `migrateResult` enum — update this function when changing migration behavior.

## Patterns from hal/archive-command (2026-02-04)

- Archive package (`internal/archive`) is the single source of truth for archiving/restoring feature state. Use `archive.Create`, `archive.List`, `archive.Restore`, and `archive.FeatureFromBranch` instead of duplicating logic.
- `archive.FeatureFromBranch` is the canonical branch-name parser (trims `hal/` prefix). `convert.go` delegates to it.
- Keep file-name constants in internal/template (e.g., `template.AutoStateFile`) and reference them from other packages; use a package-level var when a constant depends on template values.
- The `featureStateFiles` slice in `internal/archive/archive.go` defines which files get archived. Update it when adding new state files.
- Legacy auto PRD backups use a separate glob (`auto-prd.legacy-*.json`): keep both `CreateWithOptions` and `HasFeatureStateWithOptions` in sync so archive create works whether legacy artifacts are present or absent.
- Archive directories are named YYYY-MM-DD-feature and list parsing expects the date in name[:10]; keep this naming consistent for reliable listing.
- Archive CLI commands follow the Cobra parent-subcommand pattern and prompt for missing names using `bufio.NewReader(os.Stdin)` with a default derived from prd.json branchName.
- Archive tests use `t.TempDir()` and helper functions (`writePRD`, `writeFile`) for clean setup — follow this pattern for new archive-related tests.

## Patterns from compound/archive-cross-device-fallback (2026-02-04)

- Use `moveFile` and `moveDir` from `internal/archive/move.go` instead of raw `os.Rename` for any file/directory moves — they handle EXDEV (cross-device) errors via copy-and-remove fallback.
- Archive CLI handlers (`cmd/archive.go`) are extracted into testable functions: `runArchiveCreate(halDir, name, in, out)`, `runArchiveListFn(halDir, verbose, out)`, `runArchiveRestoreFn(halDir, name, out)` — following the `migrateConfigDir` pattern from `cmd/init.go`.
- CLI tests in `cmd/archive_test.go` use `strings.NewReader` for stdin simulation, `bytes.Buffer` for output capture, and `t.TempDir()` for isolation — reuse the `writePRD` and `writeFile` helpers for setup.

## Patterns from hal/goreleaser-cicd (2026-02-05)

- Version metadata is wired via ldflags into cmd package variables: cmd.Version, cmd.Commit, and cmd.BuildDate.
- Platform-specific process attributes must go through newSysProcAttr in sysproc_unix.go/sysproc_windows.go; engine code should not touch syscall.SysProcAttr directly.
- GoReleaser v2 configs require version: 2, archives use formats (list), Homebrew uses homebrew_casks with repository, and target exclusions go under ignore.
- GoReleaser CI checks need full tag history, so actions/checkout must use fetch-depth: 0.

## Patterns from hal/factory-artifact-collection (2026-06-21)

- Factory artifact payloads are stored under the global factory store `artifacts/<run-id>/`; use `factory.Store.SaveArtifactFile` for copying and metadata updates, and `factory.Store.ResolveArtifactPath` before reading stored paths.
- Artifact persistence must not write payloads into the project `.hal/` directory; tests should use temp store roots and assert project `.hal` remains free of artifact payload state.
- Local factory artifact collection should preserve legacy display `path` values while also populating store-backed `sourcePath`/`storedPath`; use stable artifact IDs for deterministic filenames when multiple artifacts share a display name.
- Factory status/doctor snapshots are generated from structured packages (`internal/status.Get`, `internal/doctor.Run`) via injectable `factoryRunDeps` hooks, then materialized as JSON artifacts and saved through `Store.SaveArtifactFile`.
- PR/CI factory outcome artifacts are derived from `compound.CIState` in `.hal/auto-state.json`; persist safe PR metadata there in `runPRStep`, and materialize stored JSON artifacts plus warning-only partial records when outcome state is unavailable.
- Sandbox artifact collection should go through `factory.SandboxArtifactCopier` and `factory.CollectSandboxArtifacts`; treat remote paths as copier inputs only, persist safe display `path`/`storedPath` metadata, and represent optional missing remote artifacts as partial warning records.
- Factory artifact read-only JSON surfaces should use command-specific safe response structs instead of raw `factory.ArtifactReference`; omit `sourcePath`/`url`, keep display `path` plus store-relative `storedPath`, and sanitize summary/warning values that contain secrets or raw IP addresses.

## Patterns from compound/compound-pipeline-foundations (2026-02-05)

- LoadConfig in internal/compound/config.go uses rawAutoConfig with pointer fields (*string, *int) for YAML unmarshaling to distinguish missing keys (nil → use default) from explicit empty values (non-nil → pass through to Validate).
- AutoConfig.Validate() checks 3 fields: ReportsDir non-empty, BranchPrefix non-empty, MaxIterations > 0. Error messages follow the format "auto.<field> must not be empty" / "must be greater than 0".
- runInit in cmd/init.go uses relative paths (.hal, .) so tests must os.Chdir to a temp directory and restore with t.Cleanup. runInit(nil, nil) works for testing.
- FindLatestReport skips hidden files (dot prefix) and directories. FindRecentPRDs matches prd-*.md in .hal/ and returns nil (not error) for missing directories.

## Patterns from hal/consolidate-progress-files (2026-02-05)

- progress.txt is the single source of truth for both manual (`hal run`) and auto (`hal auto`) workflows. The separate auto-progress.txt file was consolidated.
- When removing a constant from internal/template/template.go, also update all usages in tests and other packages (archive, compound) to maintain compilation.
- Migration logic for legacy files (like auto-progress.txt) uses append-with-separator strategy: if destination has content, append with "---" divider; if empty/default, replace entirely.
- The `hal cleanup` command removes orphaned files via centralized `orphanedFilePatterns`/`orphanedDirs` lists — add exact names or globs (for timestamped artifacts) when deprecating state files, and always provide --dry-run flag for preview.
- hal review gathers context from JSON PRDs (prd.json, auto-prd.json) in addition to markdown PRDs for accurate task completion reporting. The JSON files contain the `passes` field showing which stories are complete.
- Use template constants (template.HalDir, template.ProgressFile, etc.) for all .hal/ paths instead of hardcoded strings to ensure consistency across the codebase.

## Patterns from hal/consolidate-progress-files (2026-02-05)

- Use template.HalDir and template.ProgressFile for any .hal path construction (avoid hardcoded ".hal" or filenames) to keep CLI and review tooling consistent.
- When migrating legacy .hal state files, merge content into the new target with a separator if both have content, then delete the legacy file after a successful merge.
- Treat orphaned legacy files via a dedicated cleanup command that supports --dry-run and uses centralized file-pattern + directory lists so both exact files and globbed legacy backups are easy to extend.
- Review context should load both markdown PRDs and JSON PRDs (prd.json, auto-prd.json) because JSON includes pass/fail completion status.

## Patterns from hal/refresh-templates (2026-02-10)

- runInit is invoked as runInit(nil, nil) in tests, so Cobra flag reads must be guarded with if cmd != nil before calling cmd.Flags().GetBool/GetString.
- Use template.DefaultFiles() as the single source for core .hal template refresh targets instead of duplicating a filename list.
- For cmd package behavior with side effects, extract a run<Feature> helper that accepts io.Writer (like refreshTemplates) and keep Cobra handlers focused on flag binding and delegation.
- Template text migrations belong in migrateTemplates via replaceFileContent, normalizing multiple legacy prompt variants into one canonical guidance line.
- In cmd tests, reuse shared helpers from archive_test.go (writeFile/writePRD) and validate timestamped backup artifacts with filepath.Glob(filename+".*.bak").

## Patterns from hal/sandbox-implementation (2026-02-14)

- Extract command behavior into `run<Command>` helpers (accepting `dir`, `io.Reader`/`io.Writer`, and injected function types), and keep Cobra `RunE` focused on flags and delegation.
- Use `compound.LoadDaytonaConfig(dir)` and `compound.SaveConfig(dir, cfg)` with project-root `dir` (not `.hal/`), relying on map-based YAML round-trip to preserve unrelated config sections.
- Enforce auth via `sandbox.EnsureAuth(apiKey, setupFn, reloadFn)` callbacks from `cmd` to `internal/sandbox` to avoid circular dependencies while still supporting interactive setup.
- Treat `.hal/sandbox.json` as authoritative runtime state through `sandbox.SaveState/LoadState/RemoveState` and template constants; remove state only after successful remote delete.
- For PTY shell integration, use one read path (`PtyHandle.Read` or `DataChan`) and pair it with OS-specific resize handlers (`shell_resize_unix.go`/`shell_resize_windows.go`).

## Patterns from hal/report-review-split (2026-02-15)

- Review-loop output schema should stay centralized in `internal/compound/types.go` (`ReviewLoopResult`, `ReviewLoopTotals`, `ReviewLoopIteration`) so command output and report artifacts share one contract.
- For contract tests, assert both JSON key names and marshal/unmarshal round-trip to prevent accidental JSON tag regressions.
- For command splits, keep legacy behavior in its own command and extract execution into a `run<Command>WithDeps` helper so tests can stub engine/review dependencies without spawning real CLIs.
- Preserve legacy CLI output via a focused renderer helper (e.g., success + summary/recommendations) so renamed commands keep user-facing behavior stable during migrations.
- For `hal review` argument work, keep parsing/validation in a dedicated helper (`parseReviewRequest`) and inject branch checks via deps (`runReviewWithDeps`) so tests can verify invalid iteration and missing-branch errors without invoking real git refs.
- For review-loop iterations, keep git/codex interactions behind injectable deps (`runCodexReviewLoopWithDeps`, `reviewIterationDeps`) so tests can verify diff usage, prompt schema, and parsed counts without invoking real CLIs.
- Review-loop iteration execution now uses a two-step Codex contract: first emit strict review JSON (`issues[]` with id/title/severity/file/line/rationale/suggestedFix), then send a fixed follow-up prompt for validation+autofix JSON (`issues[]` with id/valid/reason/fixed`) and derive valid/invalid/fixes counts from issue IDs.
- Use `git merge-base <base> HEAD` + `git diff <merge-base>` for iteration diff context so uncommitted fixes from the previous iteration remain visible in the next review pass.
- Keep loop orchestration separate from per-iteration execution (`runCodexReviewLoop` vs `runReviewIteration`) so stop conditions can evolve without touching prompt/diff parsing internals.
- `ReviewLoopResult.StopReason` currently uses `no_valid_issues` (early stop when an iteration reports `ValidIssues == 0`) and `max_iterations` (requested cap reached); tests should cover both paths and verify `CompletedIterations` exactly matches executed iterations.
- Review-loop JSON artifacts are written via `compound.WriteReviewLoopJSONReport`; keep timestamp-dependent tests deterministic by using the internal `writeReviewLoopJSONReport(..., nowFn)` helper instead of stubbing wall-clock time globally.
- Keep review-loop human output in two steps: generate markdown from `compound.ReviewLoopMarkdown` (also persisted via `WriteReviewLoopMarkdownReport`) and render it at the command layer with Glamour so file artifacts and terminal output stay in sync.
- For command-split migrations, keep Cobra help text and README workflow/command-table docs in sync, and add command tests that assert required help phrases/examples so docs don’t drift from CLI behavior.

## Patterns from hal/cli-docgen-metadata-hardening (2026-02-21)

- Use `cmd.Root()` as the public accessor to the runtime Cobra command tree for tooling/tests instead of relying on package-private `rootCmd`.
- Keep CLI startup unchanged (`main.go` -> `cmd.Execute()`), and lock the accessor contract with a focused `cmd/root_test.go` test.
- Implement CLI documentation generation as a separate tool (`internal/tools/docgen`) with a testable `run(args, root)` helper so flag parsing/validation can be unit-tested without executing the real command tree.
- Set `root.DisableAutoGenTag = true` before invoking Cobra doc generators (`GenMarkdownTree`, `GenManTree`, `GenReSTTree`) to keep generated artifacts deterministic.
- Restrict `-frontmatter` to markdown output and fail fast for invalid format combinations so docgen behavior is explicit and predictable.
- Make `docs-cli` generate into a temporary directory (e.g., `docs/cli.tmp`) and replace `docs/cli` only after successful generation so stale command pages are removed safely.
- For baseline docs-artifact stories, verify determinism by running `make docs-cli` twice and ensuring there is no `docs/cli` diff before marking the story complete.
- Implement `docs-check` as clean temp generation + recursive diff against `docs/cli`; this catches both modified content and stale leftover doc files.
- In CI, run `make docs-check` with `make vet` and `make test` so docs drift and metadata regressions fail in pull requests.
- Keep command-metadata scope checks in a shared test helper that excludes hidden/deprecated commands, autogenerated `help [command]`, and `IsAdditionalHelpTopicCommand()` nodes while still including parent commands that have in-scope child pages.
- Keep user-facing command examples in Cobra `Example` fields (not just prose in `Long`) and lock required metadata (`Use`, `Short`, `Long`, `Example`) with focused table-driven command tests.
- Add a global recursive metadata contract test (`cmd/docs_metadata_test.go`) that walks all in-scope commands from `cmd.Root()` and reports command path + missing fields for fast triage.
- For family-level metadata contracts, recurse through in-scope descendants under each top-level command family (for example `archive`) and assert each command's `Example` includes its command path.
- When adding a new required top-level command family, update both core command metadata coverage (`TestCoreCommandsHaveCompleteMetadata`) and family-level metadata coverage so the family is enforced in both tables.
- Keep focused family tests (for example `cmd/ci_test.go`) asserting required `Long` help phrases plus key `Example` lines so help text regressions are caught alongside metadata-field checks.
- When a command family may not exist in every branch (for example `sandbox`), make that family optional in focused tests while keeping required families strict.
- Keep a dedicated README `CLI Reference` section linking `docs/cli/` and `docs/cli/hal.md` so generated command docs are easy to discover.

## Patterns from hal/convert-explicit-archive-force (2026-02-23)

- `cmd/convert.go` uses a `runConvertWithDeps` helper + `convertDeps` struct so tests can assert flag wiring (`--archive`, `--force`, `--granular`, `--branch`) without invoking real engines.
- Conversion safety controls are passed through `prd.ConvertOptions`; when `Archive` is true and output is not canonical `.hal/prd.json`, return the exact guard error: `--archive is only supported when output is .hal/prd.json`.
- Markdown source resolution for convert should stay deterministic in `internal/prd/convert.go`: newest `prd-*.md` by mtime wins, and equal mtimes must use lexicographic filename ascending as tie-break.
- Missing auto-discovered markdown should return an actionable error (`run \`hal plan\` or pass an explicit markdown path`), and `ConvertWithEngine` should emit `Using source: <path>` via the display writer before prompting.
- Convert archiving is strictly opt-in: only run `archive.HasFeatureStateWithOptions` / `archive.CreateWithOptions` when `ConvertOptions.Archive` is true; default convert runs must not create archive entries.
- When archiving during convert, pass `archive.CreateOptions{ExcludePaths: []string{mdSource}}` so the markdown source being converted is not moved into the archive.
- Canonical convert branch protection belongs in `internal/prd/convert.go`: compare existing `.hal/prd.json` `branchName` with converted output and block mismatches only when both are non-empty and neither `--archive` nor `--force` is set; keep the guard message exact (`branch changed from <old> to <new>; run 'hal convert --archive' or 'hal archive' first, or use --force`).
- Branch precedence for convert is explicit-option first: when `ConvertOptions.BranchName` is set, it overrides markdown-derived branch resolution and must be pinned in both the prompt guidance and final `prd.json`.
- Use the exported helpers `prd.FindNewestMarkdown` (newest `prd-*.md` with mtime + lexicographic tie-break) and `prd.ResolveMarkdownBranchName` (metadata → title slug → filename slug) instead of re-implementing source/branch resolution logic in callers.
- If branch resolution still yields empty after metadata/title/filename fallbacks, treat it as a blocking convert error (`...pass --branch`) rather than allowing a silent empty branchName.
- `runConvertWithDeps` writes display output through `os.Stdout`; command tests that need to assert streamed lines like `Using source: ...` should capture stdout (e.g., via `os.Pipe`) around the helper invocation.
- When convert behavior changes, keep `cmd/convert.go` long help and README convert docs aligned, and add/update command help tests for required safety/source phrases to prevent documentation drift.

## Patterns from autoresearch/remove-tool-references (2026-03-18)

- Browser verification is tool-agnostic: `template.BrowserVerificationCriterion` uses generic text ("Verify in browser (skip if no dev server running, no browser tools available, or 3 attempts fail)") with no tool-specific names.
- There is no `BrowserVerificationSkillName` constant — agents discover available browser tools at runtime via their skills directory.
- The `hal-pinchtab` skill was removed from embedded skills. It should not be re-added. If a user needs pinchtab support, they install the skill locally.
- Migration code in `migrateTemplates` uses regex section replacement (not exact string matching) to normalize legacy prompt sections. The `devBrowserMigration` regex matches any "Verify in browser using [tool-name]" pattern generically.
- When removing tool-specific references, keep migration code that handles user `.hal/` files from older versions — users may have prompts with old tool names that need migrating.
- Test tool-specific migration using generic tool names (e.g., "legacy-tool") rather than real tool names to avoid re-introducing references.

## Patterns from autoresearch/hal-ux-machine-readability (2026-03-18)

- New machine-readable surfaces (`--json` flag) must ship with: contract doc in `docs/contracts/`, example JSON payloads, field-locking tests in `cmd/machine_contracts_test.go`, and doc-code sync tests in `cmd/contracts_doc_test.go`.
- For nested durable contract objects, use reflection-backed JSON tag checks in `cmd/contracts_doc_test.go` so documented field names stay synchronized with implementation structs.
- Workflow state classification lives in `internal/status` — a pure filesystem package with no engine or config dependencies. The `cmd/status.go` wrapper adds engine from config.
- Health/readiness checks live in `internal/doctor` — each check has `scope` (repo/engine_local/engine_global/migration) and `applicability` (required/optional/not_applicable) fields. The check order is locked by `TestRun_CheckCount`.
- For doctor checks that depend on GitHub context (`github_auth`), treat non-git directories, missing `origin`, and non-GitHub remotes as `status=skip` + `applicability=not_applicable`; only emit a warning with remediation `gh auth login` (`Safe=false`) when a valid GitHub remote lacks authentication.
- The Codex linker uses `codexHome()` which prefers `$HOME` over `os.UserHomeDir()` so tests can isolate global link operations via `t.Setenv("HOME", tmpDir)`. All init tests must use `t.Setenv("HOME", dir)`.
- Tests that walk the shared global `Root()` Cobra command tree must NOT use `t.Parallel()` (race condition on Cobra command state).
- The `hal continue` command is the single entry point for "what to do next" — it combines status + doctor, blocks readiness only on doctor failures, and keeps warning-only doctor output advisory.
- Status auto-state semantics are single-pipeline: emit `state=auto_active` when `.hal/auto-state.json` exists with `step != done`, emit `state=auto_inactive` when `step == done`, and normalize legacy step names (`prd/explode/loop/pr`) to unified step names before rendering status detail.
- The `hal repair` command auto-applies safe remediations from doctor results. To add a new remediation, add `Remediation: &Remediation{Command: "...", Safe: true}` to the check and register the command in `executeRepairCommand`.
- The `hal links` command group (status/refresh/clean) manages engine skill links separately from `hal init`. Use `hal links refresh codex` for targeted Codex link updates.
- Doctor checks for link health should suggest `hal links refresh` or `hal links clean` instead of `hal init` — more targeted remediation.

## Patterns from hal/multi-sandbox-management (2026-03-21)

- Global sandbox path resolution in `internal/sandbox/global.go` must follow this exact precedence: `$HAL_CONFIG_HOME` → `$XDG_CONFIG_HOME/hal` → `$HOME/.config/hal`.
- Tests for global sandbox paths should isolate with `t.Setenv("HAL_CONFIG_HOME", tmpDir)`; for fallback behavior, also set `HOME` explicitly so results are deterministic.
- `EnsureGlobalDir()` should create both the global root and `sandboxes/` with `os.MkdirAll(..., 0700)` and remain safe to call repeatedly.
- Global sandbox config lives at `GlobalDir()/sandbox-config.yaml`; `LoadGlobalConfig` should merge pointer-based raw YAML fields into `DefaultGlobalConfig()` so missing keys keep defaults while explicit zero/empty values are preserved.
- `SaveGlobalConfig` should persist `sandbox-config.yaml` via temp-file + rename with `0600` permissions (same atomic durability pattern as registry writes).
- `internal/sandbox/migrate.go` config migration should treat global config as authoritative: if `sandbox-config.yaml` already exists, skip local migration; otherwise copy only local `.hal/config.yaml` `sandbox`/`daytona` sections, preserving the local file unchanged.
- Commands should opt into migration via `runSandboxAutoMigrate(projectDir, out)`; migration failures are non-fatal and must emit exactly `warning: sandbox migration failed: <error>`.
- `hal sandbox setup` should source defaults from `sandbox.LoadGlobalConfig()` and persist via `sandbox.SaveGlobalConfig()` so it works outside project directories; command tests should isolate with `HAL_CONFIG_HOME` temp dirs.
- During the transition away from project-scoped sandbox config, setup mirrors values back into `.hal/config.yaml` only when `.hal/` exists (`saveLegacyProjectSandboxConfigIfPresent`) to preserve legacy command compatibility.
- Global sandbox registry entries live at `SandboxesDir()/"<name>.json"`; writes should stay atomic (`.tmp` + `os.Rename`) with `0600` file mode.
- Registry collision semantics are strict: `SaveInstance` must return the exact error `sandbox "<name>" already exists`, while `ForceWriteInstance` is the explicit overwrite path for `--force` flows.
- `ListInstances` should treat a missing `sandboxes/` directory as empty state and return instances sorted by `Name`; missing `LoadInstance`/`RemoveInstance` errors should wrap `fs.ErrNotExist` for `errors.Is` checks.
- `ResolveDefault(filter)` is the canonical no-name target resolver: return exact empty-state errors (`no sandboxes found` or `no running sandboxes` for running-only filters), ambiguity errors as `multiple sandboxes found: <sorted names>`, and success hint text `connecting to only active sandbox "<name>"`.
- Provider lifecycle/connection methods now consume `*ConnectInfo` (`Stop`, `Delete`, `Status`, `SSH`, `Exec`). Command paths should build it via `ConnectInfoFromState(instance)` and pass explicit fallback IDs/names when deleting by raw target value.
- DigitalOcean provider semantics are ID-first: `Stop`/`Delete`/`Status` should target `info.WorkspaceID` (droplet ID), while `SSH`/`Exec` should use `info.IP` directly.
- During provider migration, remove `.hal/sandbox.json` (`LoadState`) fallbacks as each provider adopts `ConnectInfo`; SSH/Exec should require `info.IP` and fail fast when missing.
- Once all providers are fully `ConnectInfo`-based, remove obsolete shared `ProviderConfig` wiring (for example `StateDir`) and related command/test plumbing to keep the provider contract minimal.

## Patterns from hal/sandbox-uuidv7-generation (2026-03-21)

- `internal/sandbox/uuid.go` uses an injectable `UUIDSource` (`clock func() time.Time`, `rand io.Reader`) so UUID generation stays deterministic in tests while defaulting to `crypto/rand.Reader` in production.
- UUIDv7 monotonic behavior is maintained by reseeding randomness only when millisecond timestamps advance; otherwise increment the stored random bits (with timestamp carry on overflow) before formatting.
- UUID tests should assert canonical 8-4-4-4-12 format and bit-level contracts (version nibble `0x7`, variant top bits `0b10`) plus a reader-failure error path.

## Patterns from hal/sandbox-name-validation (2026-03-21)

- Keep sandbox-name validation centralized in `internal/sandbox/name.go` (`ValidateName`) with the exact user-facing error strings: `must be 1-59 chars`, `must be lowercase alphanumeric and hyphens`, `must not start or end with hyphen`, and `must not contain consecutive hyphens`.
- `SandboxNameFromBranch` should always produce a valid default name by lowercasing, replacing non `[a-z0-9]` runs with a single hyphen, trimming edge hyphens, and capping to 59 chars (falling back to `sandbox` if sanitization is empty).
- `BatchNames(base, count)` should compute suffix width as `max(2, digits(count))`, reject `count < 1`, preflight `len(base)+1+width <= 59`, and validate each generated `{base}-NN...` value via `ValidateName`.
- Name validation tests are table-driven and include boundary cases (59/60 chars) plus structural invalid cases (uppercase, special chars, edge/consecutive hyphens); keep this matrix updated when name rules change.

## Patterns from hal/sandbox-state-type (2026-03-21)

- Keep sandbox lifecycle status values centralized in `internal/sandbox/types.go` constants (`StatusRunning`, `StatusStopped`, `StatusUnknown`) instead of duplicating string literals across commands/providers.
- `SandboxState` JSON tags are camelCase with selective `omitempty`; preserve this contract with focused marshal/unmarshal key assertions in `internal/sandbox/types_test.go` when adding or renaming fields.

## Patterns from compound/single-auto-state-migration (2026-03-29)

- Auto pipeline resume migrations in `internal/compound/pipeline.go` should unmarshal through a raw compatibility struct (`rawPipelineState`) and then normalize into `PipelineState`; this keeps legacy field handling isolated from runtime logic.
- Legacy auto-state mappings are explicit and literal: `prd -> spec`, `explode -> convert`, `loop -> run`, `pr -> ci`, and `prdPath -> sourceMarkdown` when canonical `sourceMarkdown` is absent.
- Keep save/load contracts asymmetric during migration: `saveState` writes only unified fields (`sourceMarkdown`, `validation`, `run`, `review`, `ci`), while `loadState` accepts both unified and legacy keys.
- Lock migration behavior with focused state tests that assert both legacy mapping paths and round-trip JSON key presence/absence (new keys present, legacy keys omitted).

## Patterns from hal/explode-convert-shim (2026-03-29)

- Keep `cmd/explode.go` as a thin compatibility shim: call conversion through `prd.ConvertWithEngine` with `prd.ConvertOptions{Granular: true, BranchName: explodeBranchFlag}` and always target canonical output `filepath.Join(template.HalDir, template.PRDFile)`.
- The explode deprecation warning is part of the compatibility contract and must be emitted to stderr exactly as `warning: 'hal explode' is deprecated; use 'hal convert --granular'.`.
- Preserve explode machine output compatibility with the existing `ExplodeResult` JSON shape even while routing execution through convert logic.

## Patterns from compound/auto-prd-startup-migration (2026-03-29)

- Legacy auto PRD migration is centralized in `internal/compound/migrate.go` (`MigrateLegacyAutoPRD`) and should be invoked at `hal auto` startup before pipeline execution.
- Migration semantics are asymmetric: if `.hal/prd.json` is missing, rename `.hal/auto-prd.json`; if both are semantically equal JSON, delete legacy `.hal/auto-prd.json`; otherwise keep `.hal/prd.json` authoritative and preserve legacy data as `.hal/auto-prd.legacy-<ts>.json`.
- Warnings for preserved legacy auto PRDs must go to stderr so stdout stays clean for machine-readable command output.
- Migration tests should inject time (`migrateLegacyAutoPRDWithNow`) to make timestamped legacy backup assertions deterministic.

## Patterns from hal/prd-audit-legacy-auto-prd (2026-03-29)

- `hal prd audit` should treat `.hal/auto-prd.json` and `.hal/auto-prd.legacy-*.json` as migration artifacts, reported as migration issues instead of active manual/auto PRD conflicts.
- Keep legacy artifact issue text actionable by including the exact `.hal/...` artifact paths and cleanup guidance (`hal auto` migration, `hal cleanup` removal).

## Patterns from compound/auto-entry-resolution (2026-03-29)

- `hal auto` now accepts at most one positional markdown path (`auto [prd-path]`), so command arg contracts should use `maxArgsValidation(1)` and include a dedicated args test for zero/one/two-arg cases.
- Pipeline start-state selection belongs in `newInitialState(opts)`: with `SourceMarkdown`, set `step=branch`, keep `sourceMarkdown`, and derive `branchName` via `prd.ResolveMarkdownBranchName`; without it, start at `step=analyze`.
- Auto report preflight (`FindLatestReport`) must be skipped when a positional markdown source is provided, and dry-run command tests should lock both entry flows (`analyze -> spec -> branch -> convert` vs `branch -> convert`).
- Command-level integration coverage for positional markdown entry should run through `cmd.Root()` with `hal auto --dry-run <prd-path>`, assert branch slug derivation from markdown title plus skipped analyze/spec steps, and reset root/flag state between tests to avoid shared Cobra state leakage.
- Command-level integration coverage for report-driven entry should run through `cmd.Root()` with `hal auto --dry-run --report <report>`, assert step order `analyze -> spec -> branch -> convert`, and keep fixture reports local to the temp test directory for deterministic behavior.

## Patterns from compound/auto-json-v2-resume-guards (2026-03-29)

- `hal auto --json` should always emit contract version 2 with a fixed `steps` object that includes every required step key (`analyze` through `archive`) and valid status enums, even on failure paths.
- Build auto JSON via shared helpers so early returns (config/engine/report preflight/resume errors) and pipeline outcomes stay on the same contract shape.
- When `--resume` is set, ignore positional markdown paths and `--report` overrides before preflight checks, and emit explicit stderr warnings (`warning: --resume ignores ...; using saved state`) for deterministic script behavior.

## Patterns from compound/branch-step-idempotency (2026-03-29)

- Branch-step execution should use `EnsureBranchInDir(dir, branchName, baseBranch)` so retries are idempotent: no-op when already on target, checkout when target exists, and create from base only when missing.
- Git operations in compound pipeline helpers must run with `cmd.Dir = pipeline dir` to avoid mutating the caller's current working repository during tests and multi-repo usage.
- For branch-step behavior, use temp-repo unit tests that commit a base branch and assert all three paths (already-on-target, existing-branch checkout, missing-branch creation) plus repeated retry success.

## Patterns from compound/post-convert-branch-invariant (2026-03-29)

- The auto convert step should delegate through an injectable `convertWithEngine` variable (defaulting to `prd.ConvertWithEngine`) so tests can assert convert options without invoking real engines.
- Convert step calls must pin deterministic options: `prd.ConvertOptions{Granular: true, BranchName: state.BranchName}` and canonical output path `.hal/prd.json`.
- After convert, fail fast if `state.branchName` and `.hal/prd.json` `branchName` diverge (or the file is missing `branchName`), and return an actionable remediation message (for example rerun `hal convert --granular --branch <branch>` before resume).
- Cover post-convert invariant behavior with focused tests for matching branch success, mismatched branch failure, and missing-branch failure.

## Patterns from compound/validate-gate-bounded-repairs (2026-03-29)

- Auto pipeline execution should include an explicit `validate` step between `convert` and `run`; convert advances to `StepValidate`, and validation retries route back to `StepConvert`.
- Keep validation testable via an injectable `validateWithEngine` variable (defaulting to `prd.ValidateWithEngine`) so pipeline tests can simulate pass/fail/error outcomes without invoking real engines.
- Persist validation telemetry in `state.Validation` on every attempt (`attempts` counter + status values like `repairing`, `passed`, `failed`) so resumes and JSON reporting can reflect gate progress.
- Bound validation retries with a single shared limit (currently 3 attempts); on non-terminal failures, save state and retry convert, and on terminal failure, save failed telemetry before returning an actionable blocking error.

## Patterns from compound/run-gate-completion-enforcement (2026-03-29)

- Keep run-gate loop execution injectable via a package-level `runLoopWithConfig` wrapper around `loop.New(...).Run` so tests can assert loop wiring without invoking real engine sessions.
- The auto run step must execute against canonical `.hal/prd.json` (`template.PRDFile`) and block step advancement when loop completion is false.
- Persist `state.Run` telemetry (`iterations`, `complete`, `maxIterations`) on both success and blocked-incomplete paths before returning so resume/report layers can rely on saved run state.

## Patterns from compound/review-report-gates (2026-03-29)

- Auto pipeline flow now continues `run -> review -> ci -> report`; successful run-step completion should advance to `StepReview` rather than jumping directly to CI.
- Keep review/report gates injectable for tests: `runReviewLoopWithDisplay` defaults to `RunReviewLoopWithDisplay`, and `runReportWithEngine` defaults to `Review`.
- The report gate is responsible for persisting the generated artifact path into `state.ReportPath` before advancing, so downstream steps (for example archive/CI flows) can reuse the latest report.

## Patterns from compound/ci-skip-semantics (2026-03-29)

- Treat `--no-ci` as the canonical auto flag for disabling CI in auto runs.
- In `runPRStep`, persist CI telemetry via `state.CI` with explicit skipped reasons (`skip_ci_flag`, `ci_unavailable`) so skip outcomes remain machine-readable and testable.
- Keep CI dependency detection injectable (`checkCIDependencies`) so pipeline tests can cover unavailable-tool skip behavior without mutating PATH.
- Command-level CI-disable coverage should run `hal auto --dry-run --report <fixture> --no-ci` through `cmd.Root()` and assert stdout CI-skip/no-push behavior.

## Patterns from compound/archive-step-report-preservation (2026-03-29)

- Auto archive-step execution should call `archive.CreateWithOptions` (via an injectable wrapper like `createArchiveWithOptions`) and pass `state.ReportPath` through `CreateOptions.ExcludePaths` so the newest generated report is preserved.
- Resolve relative `state.ReportPath` values against the pipeline working dir (`p.dir`) before passing exclusions to archive helpers; `archive` normalizes excludes against process CWD, so unresolved relative paths can miss the intended file in tests/multi-dir callers.

## Patterns from hal/embedded-skill-guidance-refresh (2026-03-29)

- Embedded conversion skills should describe `.hal/prd.json` as the canonical runtime output for the single auto pipeline, including compatibility flows.
- Keep the embedded `explode` skill explicitly marked deprecated and direct users to `hal convert --granular` so skill guidance stays aligned with CLI behavior.
- Text-only updates under `internal/skills/*/SKILL.md` do not require `internal/skills/embed.go` changes as long as skill directory names remain unchanged; run `go test ./internal/skills` to verify embed references still resolve.

## Patterns from compound/convert-granular-integration (2026-03-29)

- Command-level integration tests for `hal convert` can stay deterministic by registering a test-only engine via `engine.RegisterEngine`, invoking `cmd.Root()` with real args, and asserting the written `.hal/prd.json` artifact rather than mocking command internals.
- Integration tests that execute through the shared Cobra tree should reset command flag `Changed` state plus package-level flag vars (for example convert flags) in `t.Cleanup` to avoid cross-test leakage.

## Patterns from compound/explode-shim-integration (2026-03-29)

- Command-level integration tests for `hal explode` should execute through `cmd.Root()` with a registered test engine and assert stderr includes the exact deprecation warning string.
- Explode compatibility coverage should verify canonical output is written to `.hal/prd.json` and that legacy `.hal/auto-prd.json` output is not recreated.
- Reset explode command flag `Changed` state and package-level explode flag vars in cleanup to prevent shared Cobra-state leakage across integration tests.

## Patterns from compound/legacy-auto-resume-integration (2026-03-29)

- Legacy resume integration coverage should seed `.hal/auto-state.json` fixtures with legacy `step` values (`prd`, `explode`, `loop`, `pr`) and run `hal auto --resume --dry-run` through `cmd.Root()`.
- Assert normalization through command output (`Resuming from step: <normalized>`) so command-level resume behavior is locked to the single-pipeline step names (`spec`, `convert`, `run`, `ci`).
- Keep legacy resume fixtures runnable by including required downstream state fields (for example `analysis` for `prd -> spec` and `sourceMarkdown` for `explode -> convert`) to avoid false negatives from unrelated step preconditions.

## Patterns from compound/dual-mode-regression-guards (2026-03-29)

- Keep `hal auto` runtime flags constrained to the single-pipeline set (`dry-run`, `resume`, `mode`, `no-ci`, `no-review`, `review-streak`, `review-max`, `report`, `engine`, `base`, `json`) and add a focused command test that fails on unexpected/legacy flag names.
- Lock the pipeline step graph with dry-run tests that assert exact step sequences for both entry modes: report discovery (`analyze -> spec -> branch -> convert -> validate -> run -> review -> ci -> report -> archive`) and positional markdown (`branch -> convert -> validate -> run -> review -> ci -> report -> archive`).
- Outside legacy migration mapping coverage, prefer canonical step constants (`StepSpec`, `StepConvert`, `StepRun`, `StepCI`) instead of legacy aliases in tests to avoid reintroducing old runtime terminology.
## Patterns from hal/ci-shared-types-contracts (2026-03-29)

- Keep CI machine-output structs centralized in `internal/ci/types.go` (push/status/fix/merge) so command handlers and pipeline integrations share one schema source of truth.
- Lock CI contract stability with both explicit `json` tags on every exported field and tests that assert required JSON keys plus marshal/unmarshal round-trip behavior (see `internal/ci/types_test.go`).
- Keep contract/version and wait-terminal-reason string values as package constants to avoid drift across commands, docs, and tests.

## Patterns from hal/ci-auth-client-selection (2026-03-29)

- Keep CI auth/client selection deterministic in `internal/ci/auth.go`: env token (`GITHUB_TOKEN` then `GH_TOKEN`) selects the API path, otherwise fall back only to authenticated `gh` CLI.
- If an env token is present but fails validation, return `ErrInvalidEnvToken` and do **not** attempt `gh` fallback; this guard is locked with tests in `internal/ci/auth_test.go`.
- Keep user-facing auth guidance as exact sentinel errors (`ErrInvalidEnvToken`, `ErrNoGitHubAuth`) so command output remains stable and testable across CI command implementations.

## Patterns from hal/ci-origin-remote-validation (2026-03-29)

- Centralize CI repo detection in `internal/ci/remote.go` via `ResolveGitHubRepository` (reads `git remote get-url origin`) and `ParseGitHubRepository` (URL parsing) so all CI flows share one remote-validation path.
- Support the common GitHub remote formats (`git@github.com:<owner>/<repo>.git`, `ssh://git@github.com/<owner>/<repo>.git`, and HTTPS variants) and reject non-`github.com` remotes with actionable guidance.
- Keep origin-remote failures machine-testable with sentinel errors (`ErrMissingOriginRemote`, `ErrNonGitHubOriginRemote`) while wrapping returned errors with user-facing remediation text.

## Patterns from hal/ci-gap-free-status-aggregation (2026-03-29)

- Keep CI aggregation in `internal/ci/status.go` gap-free by fetching **both** check-runs and commit statuses with explicit pagination loops (`per_page=100`, continue until page size drops below limit).
- Lock dedupe keys to `check:<name>` for check-runs and `status:<context>` for commit statuses, and build aggregation through the shared `getStatusWithDeps` path so tests can inject paged fixtures deterministically.
- Preserve safety precedence exactly as pending > failing > passing, and treat zero-context repositories as `StatusPending` with `ChecksDiscovered=false` (never passing by default).

## Patterns from hal/ci-wait-no-checks-determinism (2026-03-29)

- Keep CI wait defaults centralized in `internal/ci/status.go` (`PollInterval=30s`, `Timeout=30m`, `NoChecksGrace=90s`) via a single defaults helper so command wiring and core behavior stay in sync.
- Implement wait-loop orchestration behind injectable deps (`waitForChecksWithDeps` with `getStatus`/`newTicker`/`after`) to keep completed/timeout/no-checks paths deterministic in unit tests without real sleeps.
- When no-checks grace expires, re-fetch status once before returning `WaitTerminalReasonNoChecksDetected` so checks that appear near the grace boundary are not misclassified.

## Patterns from hal/ci-push-pr-core (2026-03-29)

- Keep CI push/PR orchestration behind `pushAndCreatePRWithDeps` in `internal/ci/push.go` so tests can inject git/GitHub behavior without spawning real CLIs.
- Reuse existing pull requests by querying `head=<owner>:<branch>` before creation; this prevents duplicate PRs for the same branch.
- Model draft preference as pointer-based options (`PushOptions.Draft *bool`) so default behavior (`nil => draft=true`) stays distinct from an explicit non-draft request (`false`).

## Patterns from hal/ci-fix-single-attempt-safety (2026-03-29)

- Keep CI fix core behavior in `internal/ci/fix.go` as a **single attempt** (`FixWithEngine`), with command-layer retry loops built on top of it.
- Enforce fix safety guards before running the engine: aggregated status must be `failing`, engine must be non-nil, and the working tree must be clean by default (including untracked files via `git status --porcelain --untracked-files=all`).
- After engine execution, require real file changes before staging/commit/push; if no files changed, return `ErrFixNoChanges` and create no commit.

## Patterns from hal/ci-merge-safety-guards (2026-03-29)

- Keep merge orchestration behind `mergePRWithDeps` in `internal/ci/merge.go` so strategy/status/head-drift/delete-branch paths can be tested deterministically without real GitHub calls.
- Validate merge safety in this order: strategy allowlist (`squash|merge|rebase`), aggregated status guard (passing required unless `AllowNoChecks` with zero contexts), then PR head drift check (`status.SHA` vs current PR head SHA) before issuing merge side effects.
- Remote branch cleanup after merge must treat 404 as non-fatal (`ErrRemoteBranchNotFound`) and surface other deletion failures as `DeleteWarning` on `MergeResult` instead of failing an otherwise successful merge.

## Patterns from hal/compound-steppr-ci-delegation (2026-03-29)

- Stage 6A `runPRStep` in `internal/compound/pipeline.go` delegates push + PR creation to `internal/ci.PushAndCreatePR`, but still generates title/body in compound so existing PR content stays stable.
- Keep `--no-ci` and `--dry-run` branches as early returns before CI delegation to preserve StepPR behavior and avoid remote side effects.
- `Pipeline` now uses an injectable `pushAndCreatePR` function field; use this seam in unit tests (`internal/compound/pipeline_pr_test.go`) to assert StepPR behavior without invoking real git/gh commands.

## Patterns from hal/ci-command-push-wiring (2026-03-29)

- Keep CI command-layer orchestration behind `run<Cmd>WithDeps` helpers (for example `runCIPushWithDeps`) so tests can stub side-effecting core operations and git lookups deterministically.
- In `--json` mode, emit pure JSON only (no human-readable lines); lock this with tests that assert valid object-only output.
- Implement `--dry-run` at the command layer by bypassing core side effects (`PushAndCreatePR`) and returning preview data only.

## Patterns from hal/ci-status-command-wiring (2026-03-29)

- Keep `hal ci status` command-layer orchestration behind `runCIStatusWithDeps` with injectable `getStatus` / `waitForChecks` deps so tests can validate wait and non-wait paths without invoking real git/gh commands.
- Wire `--wait`, `--timeout`, `--poll-interval`, and `--no-checks-grace` directly into `ci.WaitOptions`; pass zero-value durations through so `internal/ci/status.go` remains the single source of wait defaults.
- In `--json` mode, emit only the marshaled `ci.StatusResult`; this preserves machine-readable wait terminal reasons (including `no_checks_detected`) without human-text drift.

## Patterns from hal/ci-fix-command-wiring (2026-03-29)

- Keep `hal ci fix` command-layer orchestration behind `runCIFixWithDeps` with injectable `newEngine`, `getStatus`, `waitForChecks`, and `fixWithEngine` deps so retry behavior is deterministic in tests without real engine/git/gh calls.
- Keep retries in the command layer only: call single-attempt `ci.FixWithEngine` per attempt, wait for fresh CI status between attempts, and stop with actionable errors when status remains non-passing after `--max-attempts`.
- In `--json` mode, emit only the marshaled `ci.FixResult`; validate `--max-attempts > 0` and resolve engine selection in `runCIFix` before invoking retry orchestration.

## Patterns from hal/ci-merge-command-wiring (2026-03-29)

- Keep `hal ci merge` command-layer orchestration behind `runCIMergeWithDeps` with injectable `mergePR` and `currentBranch` deps so tests can verify flag wiring and dry-run behavior without real git/gh side effects.
- Implement merge `--dry-run` at the command layer by bypassing `ci.MergePR` and returning a preview `ci.MergeResult`; this guarantees no merge/delete side effects in preview mode.
- In `--json` mode, emit only the marshaled `ci.MergeResult`; lock this with tests to prevent human-readable output from leaking into machine contracts.

## Patterns from hal/ci-doc-discoverability (2026-03-29)

- When adding or changing `hal ci` command surfaces, update the README command tables and machine-contract links together so human docs stay aligned with generated and machine-readable docs.
- Regenerate CLI docs with `make docs-cli` and verify with `make docs-check`; commit both new command pages (`docs/cli/hal_ci*.md`) and any updated parent pages (for example `docs/cli/hal.md`).

## Patterns from hal/factory-store-paths (2026-06-20)

- Factory persistent state belongs in `internal/factory.Store`, rooted at `sandbox.GlobalDir()/factory`; do not put factory run records under per-project `.hal/`.
- Use `Store.Ensure` or `EnsureStoreDir` to create `factory/`, `factory/runs/`, and `factory/timelines/` with `0700` permissions, and keep read-only list paths empty-state when directories are missing.
- Persist factory run records through `Store.SaveRun` and load them through `Store.LoadRun`; committed records live at `factory/runs/<runID>.json`, writes use `0600` temp files plus rename, and missing loads should remain compatible with `errors.Is(err, fs.ErrNotExist)`.
- Use `Store.ListRuns` when callers need full run records ordered newest-first by latest created/updated timestamp with run ID tie-breaking; keep `Store.ListRunIDs` for lexicographic ID-only listings.
- Persist factory timeline events through `Store.AppendEvent` and read them through `Store.LoadEvents`; committed timelines live at `factory/timelines/<runID>.json` as ordered JSON arrays, writes use the same `0600` temp-file-plus-rename path, and missing timelines should load as empty event lists.
- Keep factory read/list paths scoped to committed `*.json` artifacts via the shared committed-file predicate; stale `*.tmp` and `*.bak` files must remain invisible to run and timeline reads.

## Patterns from hal/factory-list-json-command (2026-06-21)

- Factory CLI surfaces live in `cmd/factory.go`; keep command logic behind injectable deps so tests can use isolated `factory.Store` roots instead of global config state.
- `hal factory list --json` uses `FactoryListContractVersion` (`factory-list-v1`) and emits `runs` as summaries from `Store.ListRuns`; omit full `artifacts` and timeline events from list output, using `artifactCount` for compact history inspection.
- `hal factory status <run-id> --json` uses `FactoryStatusContractVersion` (`factory-status-v1`) and emits full `run` plus append-ordered `timeline`; load the run before the timeline so missing run IDs return an error without writing a JSON payload.
- Read-only `hal factory` subcommands should keep command logic behind small deps structs with `defaultStore func() (factory.Store, error)`, so tests can inject `factory.NewStore(t.TempDir())` and avoid global config state.
- Factory JSON contract changes should update exact top-level key locks in `cmd/machine_contracts_test.go`, docs/example sync in `cmd/contracts_doc_test.go`, and internal DTO round-trip tests in `internal/factory/types_test.go`.
- Adding a new factory command page requires command metadata coverage plus `make docs-cli`/`make docs-check`, because generated `docs/cli/hal_factory*.md` files are part of CI drift checks.

## Patterns from hal/local-factory-run-executor-wrapping-hal-auto (2026-06-21)

- `hal factory run` command execution is wired through `factoryRunDeps` in `cmd/factory.go`; keep local pipeline invocation behind `runPipeline` so tests can avoid real engines, git/GitHub CLIs, network calls, and long-running `hal auto` work.
- Sandbox factory artifact collection is gated by `factory.ExecutorModeSandbox` during `recordFactoryRunArtifacts`; sandbox executors should persist executor mode and sandbox name before finalization, and tests should inject `sandboxCopier`/`sandboxRequests` through `factoryRunDeps`.
- Create a pending `factory.RunRecord`, persist it through `factory.Store.SaveRun`, then persist the `running` transition before invoking the pipeline dependency; command tests should verify ordering by loading the injected `factory.NewStore(t.TempDir())` inside the pipeline stub.
- `factory.RunRecord` now includes `executorMode` and source kind constants; when adding or renaming durable run fields, update `internal/factory/types_test.go`, `cmd/factory_test.go`, `cmd/contracts_doc_test.go`, and `docs/contracts/examples/factory-status-v1.json` together.
- Factory run lifecycle timeline events are recorded in the command-layer wrapper around `factoryRunDeps.runPipeline`; use `factoryRunPipelineRequest.RecordProgress` for injected progress events and keep terminal lifecycle event recording outside the wrapped `hal auto` implementation.
- Factory run artifact references are collected in the `cmd/factory.go` wrapper after the injected pipeline returns; preserve explicit source paths, use `template` constants for canonical `.hal` files, include the factory store run-record path, and keep missing optional `.hal` artifacts non-fatal.
- Factory `ArtifactReference` fields are additive/optional for compatibility: keep `name` and `type` required, retain legacy `path` for current CLI display/path matching, and use `sourcePath`/`storedPath` plus optional `sizeBytes`, `createdAt`, `summary`, `warnings`, and `partial` for richer durable metadata.
- Factory run result payloads and non-JSON summaries should be built from the saved `factory.RunRecord` and `Store.LoadEvents` after terminal status is persisted, so `hal factory run` output reflects durable state rather than transient in-memory state.
- On factory run failures, render the JSON or human result before returning the original pipeline error; this preserves actionable output while keeping non-zero CLI exit behavior.
- Factory run failure categories are constants in `internal/factory/types.go`; classify wrapped pipeline errors in `cmd/factory.go` from explicit exit codes, canonical `step <name> failed:` auto errors, and conservative message fragments, defaulting to `unknown` when context is insufficient.

## Patterns from hal/local-factory-queue-and-worker-commands (2026-06-21)

- Factory queue JSON contracts use reusable durable types in `internal/factory` (`QueueEntry`, `QueueClaim`, `QueueStatus*`) and command response DTOs in `cmd/factory_queue_contracts.go`; queue command implementations should reuse these instead of redefining JSON shapes.
- Queue contract work must update `docs/contracts/factory-queue-*.md`, `docs/contracts/examples/factory-queue-*.json`, `cmd/contracts_doc_test.go`, `cmd/machine_contracts_test.go`, and `internal/factory/types_test.go` together so field names, docs, and examples stay locked.
- Queue worker execution should keep queue-specific state in `cmd/factory_queue.go` and run lifecycle state in the shared factory execution path in `cmd/factory.go`; tests should inject `factoryQueueWorkDeps.runPipeline` rather than invoking real `hal auto`.

## Patterns from hal/factory-remote-workspace-bootstrap (2026-06-21)

- Factory bootstrap request/result DTOs live in `internal/factory` alongside durable run/timeline records; keep them independent of command/runtime dependencies, and lock exported machine-readable fields with explicit JSON tags, raw-key assertions, and round-trip tests in `internal/factory/types_test.go`.
- Bootstrap failure classification uses bootstrap-specific categories (`repo`, `auth`, `dependency`, `engine_setup`, `unknown`) in `internal/factory/bootstrap_failure.go`; keep this separate from generic factory run categories and avoid putting raw command output into timeline-ready failure messages.
- Tooling verification bootstrap belongs in `internal/factory.BootstrapVerifyTooling`; configure Hal and engine checks with `BootstrapToolingCheck`, and use `InstallCommand` only with `BootstrapOptions.InstallMissingCLIs` so missing executables classify as `dependency` while failed setup commands classify as `engine_setup`.
