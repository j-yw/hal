# PRD: Replace TypeScript Daytona Runner with Daytona Go SDK (SDK-Only Hard Cut)

## 1) Introduction / Overview

This feature replaces the existing Daytona execution path that depends on a separate Node/TypeScript `daytona-runner` HTTP service with a single Go implementation backed directly by the Daytona Go SDK.

The primary problem is operational complexity: maintaining an extra service, container, and HTTP contract increases failure surface area and deployment overhead. The new design performs a strict hard cut to SDK-only execution while preserving the existing `internal/cloud/runner/runner.go` interface and expected behavior semantics.

## 2) Goals

1. Remove the Node/TypeScript runner service and all HTTP runner code paths from the repository and deployment manifests.
2. Keep `internal/cloud/runner/runner.go` interface unchanged so callers do not require contract changes.
3. Implement one Go SDK-backed runner path using `github.com/daytonaio/daytona/libs/sdk-go@v0.141.0`.
4. Preserve functional parity and error semantics (validation behavior and wrapped errors) for runner operations.
5. Pass all required verification checks:
   - `make test`
   - `go vet ./...`
   - `go build ./...`
   - `go test ./internal/cloud/runner/...`
   - `go test ./internal/cloud/deploy/...`
   - `docker compose -f deploy/docker-compose.yml config`

## 3) User Stories

### US-001: Migrate cloud runner environment schema to Daytona SDK variables
**Description:** As a backend/platform engineer, I want runtime config to use Daytona SDK environment variables so worker processes can connect directly without the legacy HTTP runner settings.

**Acceptance Criteria:**
- [ ] `internal/cloud/deploy/config.go` removes `HAL_CLOUD_RUNNER_URL` and `HAL_CLOUD_RUNNER_SERVICE_TOKEN` fields/constants/env parsing.
- [ ] Config adds `DAYTONA_API_KEY` (required), `DAYTONA_API_URL` (optional), `DAYTONA_SERVER_URL` (legacy alias fallback), and `DAYTONA_TARGET` (optional).
- [ ] `LoadConfig` reads `DAYTONA_API_URL` first and falls back to `DAYTONA_SERVER_URL` only when API URL is unset.
- [ ] `ValidateStore` remains DB-only.
- [ ] `Validate` requires valid DB config plus `DAYTONA_API_KEY`.
- [ ] `internal/cloud/deploy/config_test.go` includes passing and failing cases for new env schema and fallback precedence.
- [ ] Typecheck passes.

### US-002: Add Daytona Go SDK dependency and SDK client constructor
**Description:** As a backend/platform engineer, I want a dedicated SDK runner client constructor so runner operations are initialized consistently with required Daytona configuration.

**Acceptance Criteria:**
- [ ] `go.mod` includes `github.com/daytonaio/daytona/libs/sdk-go v0.141.0`.
- [ ] New file `internal/cloud/runner/sdk_client.go` defines SDK client config with fields: `APIKey`, `APIURL`, `Target`.
- [ ] Constructor calls `daytona.NewClientWithConfig(types.DaytonaConfig{APIKey, APIUrl, Target})`.
- [ ] Constructor validates required config (`APIKey`) and returns wrapped errors using `%w` where applicable.
- [ ] New file `internal/cloud/runner/sdk_client_test.go` verifies constructor validation and error behavior.
- [ ] Typecheck passes.

### US-003: Implement CreateSandbox and DestroySandbox via SDK
**Description:** As a backend/platform engineer, I want sandbox lifecycle methods implemented via the SDK so provisioning and teardown no longer depend on HTTP runner endpoints.

**Acceptance Criteria:**
- [ ] `CreateSandbox` validates request presence and required image.
- [ ] `CreateSandbox` calls `client.Create(ctx, types.ImageParams{Image:req.Image, SandboxBaseParams:{EnvVars:req.EnvVars}})`.
- [ ] `DestroySandbox` gets the sandbox via `client.Get` and deletes it with `sandbox.Delete(ctx)`.
- [ ] Validation and SDK call failures return consistent wrapped errors (`%w`).
- [ ] `sdk_client_test.go` includes success and failure tests for both methods.
- [ ] Typecheck passes.

### US-004: Implement Exec command execution parity via SDK
**Description:** As a backend/platform engineer, I want command execution to preserve existing runner semantics while using Daytona SDK process APIs.

**Acceptance Criteria:**
- [ ] `Exec` validates required inputs (request object and required execution fields).
- [ ] `Exec` retrieves sandbox with `client.Get` before execution.
- [ ] `Exec` calls `sandbox.Process.ExecuteCommand`.
- [ ] `Exec` applies `options.WithCwd(req.WorkDir)` when `req.WorkDir` is set.
- [ ] `Exec` applies `options.WithExecuteTimeout(req.Timeout)` when `req.Timeout` is set.
- [ ] Errors are wrapped consistently with `%w`.
- [ ] `sdk_client_test.go` verifies option application and validation/error paths.
- [ ] Typecheck passes.

### US-005: Implement StreamLogs via SDK session log API
**Description:** As a backend/platform engineer, I want log streaming to come directly from Daytona SDK session command logs with the existing runner return shape.

**Acceptance Criteria:**
- [ ] `StreamLogs` fetches sandbox with `client.Get`.
- [ ] `StreamLogs` reads logs via `sandbox.Process.GetSessionCommandLogs(ctx, "default", "default")`.
- [ ] `StreamLogs` returns `io.NopCloser(strings.NewReader(logs))`.
- [ ] Errors are wrapped consistently with `%w`.
- [ ] `sdk_client_test.go` covers successful log retrieval and failure cases.
- [ ] Typecheck passes.

### US-006: Implement Health using SDK list probe
**Description:** As a backend/platform engineer, I want health checks to validate Daytona reachability through SDK APIs and expose SDK version metadata.

**Acceptance Criteria:**
- [ ] `Health` probes with `client.List(ctx, nil, &page1, &limit1)`.
- [ ] Success returns `runner.HealthStatus{OK:true, Version:daytona.Version}`.
- [ ] Probe failures return wrapped errors with `%w`.
- [ ] `sdk_client_test.go` includes health success/failure tests.
- [ ] Typecheck passes.

### US-007: Remove HTTP runner implementation and references in runner package
**Description:** As a backend/platform engineer, I want the legacy HTTP runner implementation removed so there is only one supported execution path.

**Acceptance Criteria:**
- [ ] `internal/cloud/runner/client.go` is deleted.
- [ ] HTTP runner tests are removed or replaced by SDK-focused tests.
- [ ] `internal/cloud/runner/runner.go` comments no longer mention HTTP implementation.
- [ ] `go test ./internal/cloud/runner/...` passes with SDK-only implementation.
- [ ] Typecheck passes.

### US-008: Update smoke checks for SDK-direct mode
**Description:** As a backend/platform engineer, I want smoke checks to treat empty runner URL as healthy SDK-direct mode so deployments do not expect a separate runner endpoint.

**Acceptance Criteria:**
- [ ] `internal/cloud/deploy/smoke.go` treats empty runner URL as a synthetic healthy runner result.
- [ ] Existing behavior for non-empty runner URL paths remains unchanged.
- [ ] `internal/cloud/deploy/smoke_test.go` includes explicit tests for empty URL synthetic health behavior.
- [ ] Typecheck passes.

### US-009: Update deployment manifests and environment documentation
**Description:** As a backend/platform engineer, I want deployment configuration updated to SDK-only variables so compose workflows no longer reference the removed service.

**Acceptance Criteria:**
- [ ] `deploy/docker-compose.yml` removes `daytona-runner` service.
- [ ] `deploy/docker-compose.yml` removes related `depends_on` and `HAL_CLOUD_RUNNER_*` env wiring.
- [ ] Worker service includes `DAYTONA_API_KEY`, `DAYTONA_API_URL`, and `DAYTONA_TARGET` env vars.
- [ ] `deploy/.env.example` removes `HAL_CLOUD_RUNNER_*` entries and documents Daytona SDK vars.
- [ ] `docker compose -f deploy/docker-compose.yml config` succeeds.
- [ ] Typecheck passes.

### US-010: Delete TypeScript runner artifacts and complete hard-cut cleanup
**Description:** As a backend/platform engineer, I want all obsolete TypeScript runner assets removed so the repository reflects a single Go-based execution implementation.

**Acceptance Criteria:**
- [ ] `deploy/Dockerfile.daytona-runner` is deleted.
- [ ] `daytona-runner/` directory is deleted.
- [ ] Repository-wide search shows no remaining `daytona-runner` references.
- [ ] Repository-wide search shows no remaining `HAL_CLOUD_RUNNER_*` references.
- [ ] Typecheck passes.

### US-011: Run required verification suite for release readiness
**Description:** As a backend/platform engineer, I want explicit verification commands to pass so the hard cut is safe to merge.

**Acceptance Criteria:**
- [ ] `make test` passes.
- [ ] `go vet ./...` passes.
- [ ] `go build ./...` passes.
- [ ] `go test ./internal/cloud/runner/...` passes.
- [ ] `go test ./internal/cloud/deploy/...` passes.
- [ ] `docker compose -f deploy/docker-compose.yml config` succeeds.
- [ ] Typecheck passes.

## 4) Functional Requirements

- **FR-1:** The system must keep `internal/cloud/runner/runner.go` interface signatures unchanged.
- **FR-2:** The system must add `github.com/daytonaio/daytona/libs/sdk-go@v0.141.0` as a dependency.
- **FR-3:** The system must provide `internal/cloud/runner/sdk_client.go` and `sdk_client_test.go`.
- **FR-4:** SDK client config must include `APIKey` (required), `APIURL` (optional), and `Target` (optional).
- **FR-5:** SDK client constructor must call `daytona.NewClientWithConfig(types.DaytonaConfig{APIKey, APIUrl, Target})`.
- **FR-6:** `CreateSandbox` must validate request/image and create sandboxes via `client.Create` with env vars mapping.
- **FR-7:** `Exec` must validate inputs, retrieve sandbox with `client.Get`, and execute via `sandbox.Process.ExecuteCommand` with optional cwd/timeout options.
- **FR-8:** `StreamLogs` must retrieve logs through `sandbox.Process.GetSessionCommandLogs(ctx, "default", "default")` and return an `io.ReadCloser` via `io.NopCloser(strings.NewReader(logs))`.
- **FR-9:** `DestroySandbox` must get sandbox via `client.Get` and delete with `sandbox.Delete(ctx)`.
- **FR-10:** `Health` must probe via `client.List(ctx, nil, &page1, &limit1)` and return `runner.HealthStatus{OK:true, Version:daytona.Version}` on success.
- **FR-11:** Runner method errors must be consistently wrapped with `%w` and use stable, descriptive messages.
- **FR-12:** The legacy HTTP runner implementation file `internal/cloud/runner/client.go` must be removed.
- **FR-13:** Runner package comments and tests must not mention or depend on HTTP runner mode.
- **FR-14:** Deploy config must remove `HAL_CLOUD_RUNNER_URL` and `HAL_CLOUD_RUNNER_SERVICE_TOKEN`.
- **FR-15:** Deploy config must add `DAYTONA_API_KEY`, `DAYTONA_API_URL`, `DAYTONA_SERVER_URL` alias fallback, and `DAYTONA_TARGET`.
- **FR-16:** `LoadConfig` must prefer `DAYTONA_API_URL` over `DAYTONA_SERVER_URL`.
- **FR-17:** `ValidateStore` must remain DB-only.
- **FR-18:** `Validate` must require DB config and `DAYTONA_API_KEY`.
- **FR-19:** Smoke checks must treat empty runner URL as SDK-direct synthetic healthy.
- **FR-20:** `deploy/docker-compose.yml` must remove `daytona-runner` service and related env/depends_on wiring.
- **FR-21:** `deploy/.env.example` must document Daytona SDK env vars and remove `HAL_CLOUD_RUNNER_*`.
- **FR-22:** `deploy/Dockerfile.daytona-runner` and `daytona-runner/` must be deleted.
- **FR-23:** Repository must contain no remaining references to `daytona-runner` or `HAL_CLOUD_RUNNER_*`.

## 5) Non-Goals

- Introduce a dual-path runtime (SDK + HTTP fallback).
- Change the `internal/cloud/runner/runner.go` interface contract.
- Add new runner features beyond parity (new commands, new streaming protocols, new UX).
- Modify DB validation semantics beyond current requirements.
- Add frontend/UI features.

## 6) Design Considerations

- Keep command/package call sites stable by preserving the runner interface.
- Minimize migration risk by making the cutover explicit and removing legacy code paths instead of gating with feature flags.
- Keep environment variable naming and precedence explicit to reduce deployment ambiguity.

## 7) Technical Considerations

- Ensure SDK interactions are testable in `sdk_client_test.go` without relying on live Daytona endpoints (use controlled test doubles/wrappers where needed).
- Preserve error semantics expected by upstream callers (clear operation-specific prefixes + `%w` wrapping).
- Apply strict precedence for endpoint config: `DAYTONA_API_URL` > `DAYTONA_SERVER_URL` alias fallback.
- Keep smoke behavior deterministic in SDK-direct mode by returning synthetic healthy when runner URL is empty.

## 8) Success Metrics

- 100% removal of legacy runner references: no `daytona-runner` or `HAL_CLOUD_RUNNER_*` in repository.
- All required command checks pass:
  - `make test`
  - `go vet ./...`
  - `go build ./...`
  - `go test ./internal/cloud/runner/...`
  - `go test ./internal/cloud/deploy/...`
  - `docker compose -f deploy/docker-compose.yml config`
- No caller-facing interface changes required for `internal/cloud/runner/runner.go` consumers.
- Deploy config is SDK-only, with only the explicitly permitted legacy alias (`DAYTONA_SERVER_URL`) retained.

## 9) Open Questions

1. Should `DAYTONA_SERVER_URL` alias support be kept indefinitely or scheduled for deprecation in a future release?
2. Are there any downstream docs/runbooks outside this repository that still mention `daytona-runner` and require coordinated updates?
3. Should health checks eventually include target-level diagnostics (beyond current parity scope) in a follow-up PRD?