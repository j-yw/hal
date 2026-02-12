# PRD: Split Cloud Worker Runtime into `hal-worker` and Keep `hal` Lean

## 1) Introduction / Overview

`hal` currently pulls Daytona SDK dependencies into the default CLI build path. As a result, a normal local install (`make install`) downloads a large transitive graph (Daytona SDK + AWS SDK + OpenTelemetry + gRPC), even for users who only run local workflows.

We want a cleaner architecture with two binaries:

- `hal`: end-user CLI (local workflows + cloud control commands)
- `hal-worker`: operator/runtime binary for cloud execution workers (Daytona SDK path)

This separation keeps default installs fast and lightweight, while preserving cloud capabilities for deployed worker environments.

## 2) Goals

1. Make default `hal` install/build independent of Daytona SDK and its heavy transitive dependencies.
2. Introduce a dedicated worker runtime binary named `hal-worker`.
3. Keep end-user cloud UX unchanged in `hal` (`run --cloud`, `auto --cloud`, `review --cloud`, `hal cloud ...`).
4. Keep worker/runtime behavior functionally equivalent after extraction.
5. Update build/release/deploy tooling to support both binaries clearly.

## 3) User Stories

### US-001: Isolate runner interface from Daytona SDK implementation
**Description:** As a developer, I want the runner interface package to be dependency-light so that importing cloud domain packages does not pull Daytona SDK into `hal`.

**Acceptance Criteria:**
- [ ] `internal/cloud/runner` remains interface/types only (no Daytona imports).
- [ ] Daytona SDK client code is moved to a dedicated adapter package (e.g., `internal/cloud/runner/daytona`).
- [ ] Non-worker code paths in `hal` do not import Daytona SDK packages.
- [ ] Typecheck passes.

### US-002: Create a worker composition package
**Description:** As a developer, I want a single worker composition root so worker startup wiring is centralized and testable.

**Acceptance Criteria:**
- [ ] Add a worker-oriented composition package (e.g., `internal/cloud/worker`) that wires store + runner adapter + pipeline services.
- [ ] Worker startup logic is separated from end-user CLI command wiring.
- [ ] Package has unit tests for config validation and startup failure cases.
- [ ] Typecheck passes.

### US-003: Add `hal-worker` binary entrypoint
**Description:** As a platform operator, I want a dedicated executable for cloud workers so runtime deployment is explicit and independent from user CLI installs.

**Acceptance Criteria:**
- [ ] Add a new binary entrypoint at `cmd/hal-worker/main.go` (or equivalent dedicated path).
- [ ] `hal-worker --help` documents worker runtime usage.
- [ ] Worker binary starts the same cloud worker loop behavior currently expected by deployment.
- [ ] Typecheck passes.

### US-004: Keep `hal` CLI behavior unchanged for users
**Description:** As an end user, I want existing `hal` local and cloud command behavior to remain stable while internals are refactored.

**Acceptance Criteria:**
- [ ] `hal run`, `hal auto`, `hal review` behavior is unchanged.
- [ ] `hal run --cloud`, `hal auto --cloud`, `hal review --cloud` behavior is unchanged.
- [ ] `hal cloud setup|doctor|list|status|logs|cancel|pull|auth ...` behavior is unchanged.
- [ ] Existing command conformance tests pass.
- [ ] Typecheck passes.

### US-005: Update Makefile/install ergonomics for two binaries
**Description:** As a developer/operator, I want explicit install targets for user CLI vs worker runtime.

**Acceptance Criteria:**
- [ ] `make install` installs only `hal`.
- [ ] Add `make build-worker` and `make install-worker` for `hal-worker`.
- [ ] Add `make uninstall-worker`.
- [ ] Optional `make install-all` installs both binaries.
- [ ] Makefile help text is updated.
- [ ] Typecheck passes.

### US-006: Update release packaging for multi-binary artifacts
**Description:** As a release engineer, I want CI/release outputs to include both binaries with clear naming.

**Acceptance Criteria:**
- [ ] GoReleaser config includes `hal` and `hal-worker` builds.
- [ ] Archive naming clearly distinguishes binaries per OS/arch.
- [ ] Homebrew/tap strategy is documented (single formula with two binaries or split formula/cask).
- [ ] Release checks pass.
- [ ] Typecheck passes.

### US-007: Update deployment artifacts to use `hal-worker`
**Description:** As an operator, I want deployment assets to run the dedicated worker binary directly.

**Acceptance Criteria:**
- [ ] `deploy/Dockerfile.worker` builds and runs `hal-worker` instead of overloading `hal` entrypoint.
- [ ] `deploy/docker-compose.yml` worker service uses `hal-worker` command/entrypoint.
- [ ] Deployment docs/env examples are updated accordingly.
- [ ] `docker compose -f deploy/docker-compose.yml config` succeeds.
- [ ] Typecheck passes.

### US-008: Add dependency boundary regression checks
**Description:** As a maintainer, I want automated checks to prevent heavy SDK dependencies from leaking back into the `hal` binary.

**Acceptance Criteria:**
- [ ] Add CI check/assertion that `go list -deps .` for `hal` does not include Daytona/AWS OTEL/gRPC runtime packages.
- [ ] Add CI check/assertion that `go list -deps ./cmd/hal-worker` includes Daytona SDK path.
- [ ] Build/test docs include these verification commands.
- [ ] Typecheck passes.

### US-009: Document install and operating model
**Description:** As a user/operator, I want clear docs on when to install `hal` vs `hal-worker` so setup is straightforward.

**Acceptance Criteria:**
- [ ] README/docs explain binary roles and install paths.
- [ ] Cloud docs clearly state: users need `hal`; operators running worker infra need `hal-worker`.
- [ ] Migration notes describe any command/entrypoint changes.
- [ ] Typecheck passes.

## 4) Functional Requirements

- **FR-1:** `hal` build path must not compile Daytona SDK adapter packages.
- **FR-2:** Runner interface/types must remain available via dependency-light package(s).
- **FR-3:** Daytona SDK adapter must be isolated under a worker-only import path.
- **FR-4:** A dedicated `hal-worker` binary must exist and be buildable independently.
- **FR-5:** Default install target must continue to install only `hal`.
- **FR-6:** Worker install/build targets must be first-class in Makefile.
- **FR-7:** Deployment artifacts must run `hal-worker` as worker runtime.
- **FR-8:** Existing user-facing cloud command contracts in `hal` must remain stable.
- **FR-9:** Release tooling must produce artifacts for both binaries.
- **FR-10:** CI must guard against dependency-boundary regressions.
- **FR-11:** Documentation must define binary responsibilities and install choices.

## 5) Non-Goals

- Rewriting cloud workflow semantics (`submit/status/logs/pull/cancel`) in this change.
- Changing store schema or run state machine behavior.
- Introducing new end-user cloud flags or command surface.
- Replacing Daytona SDK provider in this phase.
- Building a plugin ecosystem in this phase.

## 6) Design Considerations

- Keep user mental model simple: one default CLI (`hal`) and one runtime binary (`hal-worker`).
- Avoid naming tied to current implementation details (`sandbox`) to preserve future runtime flexibility.
- Prefer explicit binary separation over hidden build-tag behavior for operational clarity.
- Keep internal package boundaries strict so dependency intent is obvious from imports.

## 7) Technical Considerations

- If needed, perform extraction in two phases:
  1. package boundary refactor (no behavior change),
  2. binary/release/deploy split.
- Ensure internal package import rules remain valid when adding `cmd/hal-worker`.
- Keep `deploy.DefaultStoreFactory` and existing store wiring patterns test-overridable (if-nil guard pattern in `cmd` package).
- Add focused tests around composition roots and startup validation.

## 8) Success Metrics

1. From clean module cache, `make install` for `hal` no longer downloads Daytona SDK dependency tree.
2. `go list -deps . | rg 'daytona|aws-sdk-go-v2|go.opentelemetry.io/otel|google.golang.org/grpc'` returns no matches for `hal`.
3. Worker binary builds and runs with Daytona SDK dependencies as expected.
4. Existing cloud CLI behavior tests remain green.
5. Release/deploy workflows produce and run both binaries correctly.

## 9) Implementation Plan (Suggested Sequence)

1. Extract Daytona SDK client into worker-only adapter package.
2. Add worker composition root package and tests.
3. Introduce `cmd/hal-worker` entrypoint.
4. Add Makefile targets (`build-worker`, `install-worker`, `uninstall-worker`, optional `install-all`).
5. Update Dockerfile/compose for worker binary.
6. Update GoReleaser for multi-binary builds.
7. Add dependency-boundary CI checks.
8. Update README/deploy docs.
9. Run verification suite and dry-run release checks.

## 10) Verification Checklist

- [ ] `make test`
- [ ] `go vet ./...`
- [ ] `go build ./...`
- [ ] `go build -o hal .`
- [ ] `go build -o hal-worker ./cmd/hal-worker`
- [ ] `docker compose -f deploy/docker-compose.yml config`
- [ ] `go list -deps . | rg 'daytona|aws-sdk-go-v2|go.opentelemetry.io/otel|google.golang.org/grpc'` (expect no output)
- [ ] `go list -deps ./cmd/hal-worker | rg 'github.com/daytonaio/daytona/libs/sdk-go'` (expect match)

## 11) Open Questions

1. Should Homebrew publish one package containing both binaries, or keep `hal-worker` as a separate package?
2. Do we need a short-lived compatibility shim for any existing internal scripts that assume worker is launched via `hal`?
3. Should worker binary versioning always mirror `hal`, or be allowed to diverge later?
4. Do we want to split worker into its own Go module now, or defer until needed?
