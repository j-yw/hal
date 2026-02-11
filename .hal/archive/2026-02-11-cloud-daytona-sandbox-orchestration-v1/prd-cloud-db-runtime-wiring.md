# PRD: Cloud DB Runtime Wiring

## Introduction/Overview

All `hal cloud` operator commands (submit, status, logs, cancel, run, pull, auth *) currently declare package-level factory variables (`cloudSubmitStoreFactory`, etc.) but never assign production defaults. Every invocation returns `"store not configured"` because the factories are nil at runtime.

This milestone wires the existing command layer to a real database backend by introducing a shared **cloud runtime** composition root that loads configuration from environment variables (with `.env` fallback via `joho/godotenv`), opens a Turso or Postgres connection once via `sync.Once`, and provides default factory implementations for all commands. The test override pattern (package-level function variables) remains intact.

## Goals

1. **Eliminate "store not configured"** — all 11 cloud commands work against a real DB when env vars or `.env` are present.
2. **Local dev convenience** — `.env` file is loaded automatically (non-overriding) so operators don't need to export vars manually.
3. **Production readiness** — fail-fast validation with clear error messages when DB configuration is missing or invalid.
4. **Zero test breakage** — existing test factory overrides continue to work; new runtime code is only activated when factories are nil.
5. **Harden Turso DSN construction** — eliminate raw string concatenation of auth tokens into URLs.

## User Stories

### US-055: Add production driver registration

**Description:** As a developer, I want SQL drivers registered at import time so that `sql.Open("libsql", ...)` and `sql.Open("pgx", ...)` work in the production binary without manual setup.

**Acceptance Criteria:**
- [ ] New file `internal/cloud/deploy/drivers.go` contains blank imports for the libsql and pgx stdlib drivers
- [ ] `sql.Open("libsql", ...)` succeeds in a non-test binary (verified by compile + `go vet`)
- [ ] `sql.Open("pgx", ...)` succeeds in a non-test binary (verified by compile + `go vet`)
- [ ] `go mod tidy` adds any missing direct dependencies
- [ ] Typecheck passes

---

### US-056: Split config validation into ValidateStore and Validate

**Description:** As a command author, I want a `ValidateStore()` method that checks only DB-related fields so that DB-only commands (status, logs, auth) don't require runner URL/token.

**Acceptance Criteria:**
- [ ] `Config.ValidateStore()` returns nil when adapter + corresponding DB fields are set, regardless of runner fields
- [ ] `Config.ValidateStore()` returns a descriptive error when adapter is invalid
- [ ] `Config.ValidateStore()` returns a descriptive error when Turso URL or auth token is missing (adapter=turso)
- [ ] `Config.ValidateStore()` returns a descriptive error when Postgres DSN is missing (adapter=postgres)
- [ ] `Config.Validate()` calls `ValidateStore()` first, then checks runner URL and token
- [ ] Table-driven tests in `config_test.go` cover all `ValidateStore()` branches (turso OK, postgres OK, invalid adapter, missing turso URL, missing turso token, missing postgres DSN)
- [ ] Existing `Validate()` tests continue to pass unchanged
- [ ] Typecheck passes

---

### US-057: Harden Turso DSN construction with net/url

**Description:** As a developer, I want the Turso DSN built using `net/url` query encoding so that auth tokens containing special characters are safely escaped.

**Acceptance Criteria:**
- [ ] New exported function `BuildTursoDSN(baseURL, authToken string) (string, error)` in `internal/cloud/deploy/store_factory.go`
- [ ] `BuildTursoDSN` uses `url.Parse` + `url.Query().Set("authToken", ...)` instead of string concatenation
- [ ] `BuildTursoDSN` returns an error for empty baseURL
- [ ] `openTurso` calls `BuildTursoDSN` instead of manual concatenation
- [ ] Unit tests for `BuildTursoDSN`: valid URL, token with special chars (`=`, `+`, `/`), empty URL error
- [ ] Existing store factory behavior is unchanged (open, ping, migrate flow)
- [ ] Typecheck passes

---

### US-058: Add cloud runtime composition root

**Description:** As a CLI developer, I want a single `cloudRuntime` struct in the `cmd` package that lazily initializes DB config, connection, and store once per process, so all commands share one connection and initialization path.

**Acceptance Criteria:**
- [ ] New file `cmd/cloud_runtime.go` defines `cloudRuntime` struct with `sync.Once`, cached config/store/db/err fields
- [ ] `cloudRuntime.Store()` returns `(cloud.Store, error)` — calls `once.Do` on first invocation
- [ ] `cloudRuntime.SubmitConfig()` returns `cloud.SubmitConfig` with `IDFunc` set to `uuid.NewString`
- [ ] `cloudRuntime.Close()` closes the cached `*sql.DB` if non-nil
- [ ] Init logic inside `once.Do`: load `.env` (non-overriding, missing file is not an error), `LoadConfigFromEnv()`, `ValidateStore()`, `OpenStore()`
- [ ] Uses `joho/godotenv` `Load()` (non-overriding); respects `HAL_CLOUD_ENV_FILE` env var for custom path
- [ ] Package-level `var cloudRuntimeDefault = &cloudRuntime{}` is created
- [ ] Typecheck passes

---

### US-059: Add cloud runtime unit tests

**Description:** As a developer, I want tests that verify the runtime's lazy-init, caching, error handling, and dotenv behavior.

**Acceptance Criteria:**
- [ ] New file `cmd/cloud_runtime_test.go` with table-driven tests
- [ ] Test: `Store()` called twice returns the same instance (init runs once)
- [ ] Test: when env vars are missing, `Store()` returns a clear error containing "no DB configured" or the validation error message
- [ ] Test: `SubmitConfig().IDFunc()` returns non-empty, unique strings across calls
- [ ] Test: missing `.env` file does not cause init failure when env vars are set directly
- [ ] Test: `Close()` is safe to call when store was never initialized
- [ ] Typecheck passes

---

### US-060: Wire default factories for cloud commands

**Description:** As an operator, I want `hal cloud submit/status/logs/cancel/run/pull` to use the DB runtime by default so commands work without any code changes to each command file.

**Acceptance Criteria:**
- [ ] In `cmd/cloud.go` `init()`, each store/config factory is assigned to the runtime default only when currently nil: `if cloudSubmitStoreFactory == nil { cloudSubmitStoreFactory = cloudRuntimeDefault.Store }`
- [ ] All 6 store factories are wired: submit, status, logs, cancel, run, pull
- [ ] Both config factories are wired: submit config, run config
- [ ] Tests that override factories before `init()` still work (nil guard prevents overwrite)
- [ ] Running `hal cloud status <any-id>` with valid `.env` no longer returns "store not configured"
- [ ] Typecheck passes

---

### US-061: Wire default factories for cloud auth commands

**Description:** As an operator, I want `hal cloud auth link/import/status/validate/revoke` to use the DB runtime by default.

**Acceptance Criteria:**
- [ ] In `cmd/cloud_auth.go` `init()`, each auth store factory is assigned to the runtime default only when currently nil
- [ ] All 5 auth store factories are wired: link, import, status, validate, revoke
- [ ] Tests that override factories before `init()` still work
- [ ] Running `hal cloud auth status <profile-id>` with valid `.env` no longer returns "store not configured"
- [ ] Typecheck passes

---

### US-062: Load dotenv in cloud env command

**Description:** As an operator, I want `hal cloud env` to load `.env` before validating so it works when keys are only defined in the dotenv file.

**Acceptance Criteria:**
- [ ] `runCloudEnv` (or the cobra `RunE` wrapper) loads `.env` using the same `joho/godotenv.Load()` pattern before calling `LoadConfigFromEnv()`
- [ ] `hal cloud env` with keys only in `.env` (not exported) prints "Environment OK" and the config summary
- [ ] Full `Validate()` is still used (runner URL/token required for env command)
- [ ] Existing `cloud_deploy_test.go` tests pass unchanged
- [ ] Typecheck passes

---

### US-063: Update deploy/.env.example with complete key set

**Description:** As an operator, I want the `.env.example` to document all supported environment variables so I know exactly what to configure.

**Acceptance Criteria:**
- [ ] `deploy/.env.example` includes all keys: `HAL_CLOUD_DB_ADAPTER`, `HAL_CLOUD_TURSO_URL`, `HAL_CLOUD_TURSO_AUTH_TOKEN`, `HAL_CLOUD_POSTGRES_DSN` (commented), `HAL_CLOUD_RUNNER_URL`, `HAL_CLOUD_RUNNER_SERVICE_TOKEN`, `HAL_CLOUD_ENV_FILE` (commented, optional), `DAYTONA_API_KEY` (commented, optional), `DAYTONA_SERVER_URL` (commented, optional)
- [ ] Each variable has a short inline comment describing its purpose
- [ ] Postgres DSN and optional keys are commented out with `#` prefix
- [ ] Typecheck passes

---

### US-064: Run full test suite and verify integration

**Description:** As a developer, I want to confirm the entire test suite passes after all wiring changes.

**Acceptance Criteria:**
- [ ] `go test ./internal/cloud/deploy/...` passes with zero failures
- [ ] `go test -v ./cmd/ -run Cloud` passes with zero failures
- [ ] `go test ./...` passes with zero failures
- [ ] `go vet ./...` reports no issues
- [ ] No secrets or DSNs are logged in error messages (review error strings in new code)
- [ ] Typecheck passes

## Functional Requirements

- **FR-1:** The system must load `.env` files using `joho/godotenv.Load()` (non-overriding) in the command runtime layer only — never inside `internal/cloud` domain packages.
- **FR-2:** The system must support `HAL_CLOUD_ENV_FILE` to specify a custom dotenv file path; when unset, it defaults to `.env` in the current directory.
- **FR-3:** The system must initialize the DB connection at most once per process via `sync.Once`, regardless of how many commands or factory calls occur.
- **FR-4:** The system must fail fast with a clear, actionable error message (e.g., "no DB configured — set HAL_CLOUD_DB_ADAPTER and required connection variables, or create a .env file") when DB configuration is missing or invalid.
- **FR-5:** The system must never overwrite process-level environment variables with dotenv values (non-overriding load).
- **FR-6:** The system must assign default factory implementations only when the package-level variable is nil, preserving the test override pattern.
- **FR-7:** The `BuildTursoDSN` function must use `net/url` to safely encode auth tokens in the query string.
- **FR-8:** The `ValidateStore()` method must check only DB-related config fields; `Validate()` must call `ValidateStore()` then additionally require runner fields.
- **FR-9:** The system must not log or include database DSNs or auth tokens in error messages.

## Non-Goals

- **NG-1:** This milestone does not add connection pooling, retry, or reconnection logic.
- **NG-2:** This milestone does not implement the serve/worker control-plane commands.
- **NG-3:** This milestone does not add a `--store-only` flag to the `env` command.
- **NG-4:** This milestone does not modify the schema or migration logic in Turso/Postgres adapters.
- **NG-5:** This milestone does not add Docker build verification (CGO_ENABLED=0 compatibility is a follow-up).
- **NG-6:** This milestone does not change the `cloud.Store` interface or add new Store methods.

## Technical Considerations

- **Driver registration:** Blank imports for `libsql` and `pgx/stdlib` must be in a file that is always compiled into the binary (not behind build tags). Placing them in `internal/cloud/deploy/drivers.go` keeps them co-located with the store factory.
- **CGO_ENABLED=0:** The `libsql` Go driver may require CGO. If it does, the Docker build must enable CGO or use a CGO-compatible base image. This is flagged as a follow-up risk, not blocking this milestone.
- **godotenv dependency:** `joho/godotenv` is a single-file, zero-dependency library. Adding it has minimal impact on binary size and dependency tree.
- **sync.Once error caching:** If the first `Store()` call fails (e.g., bad credentials), all subsequent calls return the same cached error. This is intentional — the process should be restarted with correct config rather than retrying with stale state.
- **Test isolation:** Tests that set factory overrides before `init()` runs will continue to work because `init()` uses `if factory == nil` guards. Tests that need the runtime should set env vars and use a fresh `cloudRuntime{}` instance.

## Success Metrics

1. All 11 `hal cloud` commands return meaningful DB-backed responses (not "store not configured") when env vars or `.env` are present.
2. `go test ./...` passes with zero failures and no regressions.
3. `go vet ./...` reports no issues.
4. No secrets appear in error output or logs.
5. A fresh clone with only a `.env` file can run `hal cloud auth link` and `hal cloud submit` successfully against a real Turso database.

## Open Questions

1. **uuid dependency:** Should `IDFunc` use `github.com/google/uuid` (already in go.mod?) or a lighter alternative? Needs go.mod check.
2. **Close() lifecycle:** Should `cloudRuntimeDefault.Close()` be called in a `cobra.PersistentPostRun` hook on the root command, or is relying on process exit sufficient for CLI tools?
3. **Multiple .env search paths:** Should the runtime also check `deploy/.env` as a fallback when `.env` doesn't exist in the working directory, or is a single path sufficient?
