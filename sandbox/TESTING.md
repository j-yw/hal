# Sandbox Testing

This document covers how to run sandbox smoke tests and integration tests, both locally and in CI.

## Smoke Tests (Docker)

Smoke tests verify that all tools are installed correctly inside the sandbox Docker image.

### Run locally

```bash
# Build image and run smoke tests
make sandbox-test

# Or manually:
docker build -f sandbox/Dockerfile -t hal-sandbox .
docker run --rm hal-sandbox /test.sh
```

### CI behavior

The `sandbox-build` and `sandbox-test` jobs in `.github/workflows/ci.yml` build the Docker image and run `/test.sh` on every push and PR to `main`, `develop`, `sandbox*`, and `compound/sandbox*` branches. The `sandbox-test` job uses path filtering — it only runs the smoke tests when files under `sandbox/` or the `Makefile` change.

## Integration Tests (Daytona API)

Integration tests exercise the full sandbox lifecycle against a live Daytona environment: snapshot create, sandbox start, status, exec, stop, delete, and state file management.

### Required environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `DAYTONA_API_KEY` | Yes | Daytona API key for authentication |
| `DAYTONA_SERVER_URL` | No | Daytona server URL (SDK uses its default if not set) |

### Run locally

```bash
# Set credentials
export DAYTONA_API_KEY="your-api-key"
export DAYTONA_SERVER_URL="https://your-server.daytona.io"  # optional

# Run all sandbox integration tests
go test -tags=integration -v -timeout 10m ./internal/sandbox/...
```

Without `-tags=integration`, these tests are completely excluded from compilation. Running `go test ./...` without the tag does not require Daytona credentials.

### Skip behavior

When `DAYTONA_API_KEY` is not set (empty or unset), all integration tests skip gracefully via `t.Skip` with a descriptive message. This means:

- `go test ./...` (no integration tag) always works without credentials
- `go test -tags=integration ./...` without credentials reports skipped tests, not failures
- Fork PRs that cannot access repository secrets still pass CI

### CI behavior

The `integration-test` job in `.github/workflows/ci.yml` runs integration tests on **push events only** (not pull requests) to branches matching `main`, `develop`, `sandbox*`, and `compound/sandbox*`. It depends on the `test` job passing first.

CI secrets are configured as GitHub repository secrets:

- `DAYTONA_API_KEY` — set in repository Settings > Secrets and variables > Actions
- `DAYTONA_SERVER_URL` — set in repository Settings > Secrets and variables > Actions

The job passes these secrets as environment variables to the test command:

```yaml
env:
  DAYTONA_API_KEY: ${{ secrets.DAYTONA_API_KEY }}
  DAYTONA_SERVER_URL: ${{ secrets.DAYTONA_SERVER_URL }}
```

### Test structure

Integration test files use the `//go:build integration` build tag:

| File | Tests |
|------|-------|
| `internal/sandbox/integration_helpers_test.go` | Shared helpers: `requireDaytonaEnv`, `newIntegrationClient`, `integrationHalDir` |
| `internal/sandbox/snapshot_integration_test.go` | Snapshot create and delete lifecycle |
| `internal/sandbox/lifecycle_integration_test.go` | Sandbox start, status, exec, stop, delete, and state file verification |
