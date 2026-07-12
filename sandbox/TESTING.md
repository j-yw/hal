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

## Contained Podman lab

Use `sandbox/podman-lab.sh` for local rootless Podman and `sandboxd` testing. The
script owns an isolated home directory, Hal config root, XDG config/data/cache
roots, temp root, local Hal binary, disposable repository clones, daemon socket,
image, and named Podman machine. It does not install the feature binary or write
runtime state to the normal user configuration. `seed-auth` explicitly copies
supported Codex, Pi, and Claude auth files into the isolated home when live agent
execution is required. A custom `HAL_SANDBOX_LAB_ROOT` must be absolute and use
a `hal-sandbox-*` leaf directory so teardown cannot target a broad filesystem
path.

When host TUN/DNS routing cannot reach registries directly, set separate proxy
URLs instead of disabling TLS. `HAL_SANDBOX_LAB_HOST_PROXY` is used only while
the host downloads the Podman machine image. `HAL_SANDBOX_LAB_GUEST_PROXY` is
used only for image build traffic inside the Podman VM. Neither value is stored
in the lab manifest.

```sh
export HAL_SANDBOX_LAB_HOST_PROXY=http://127.0.0.1:PORT
export HAL_SANDBOX_LAB_GUEST_PROXY=http://host.containers.internal:PORT
make sandbox-lab-prepare
make sandbox-lab-start
./sandbox/podman-lab.sh seed-auth
./sandbox/podman-lab.sh clone /path/to/browser-game browser-game
./sandbox/podman-lab.sh run -- hal sandbox host status hal-lab-worker --live
./sandbox/podman-lab.sh run -- hal factory run --sandbox --base main \
  --sandbox-host hal-lab-worker --sandbox-runtime rootless_podman
make sandbox-lab-destroy
```

Run `make sandbox-lab-destroy` after testing. It deletes registered lab
sandboxes through Hal while the daemon is available, stops the daemon, removes
remaining Hal-labeled containers, deletes the named Podman machine, and removes
the lab root.

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
