# Sandbox Runtime v2 Phase 49 Live-Provider Gates Verification

Phase 49 live-provider gate verification is fake-only by default. It keeps the
default diagnostics and E2E verification path on fake-backed run, auto, and
factory coverage while documenting existing optional live-provider gates as
manual opt-in paths only.

Fake-only verification remains the documented default path. Default Phase 49
verification does not require live credentials, KVM, Firecracker, Podman,
Docker, worker daemons, provider APIs, network access, or optional live build
tags.

## Default Verification

Run the focused default fake-only E2E and Phase 49 live-gate documentation
guards:

```sh
go test -count=1 ./cmd -run 'Test(US006DefaultFakeOnly|Phase49LiveProvider)'
```

Run the repository default test suite:

```sh
go test ./...
```

Run repository typecheck by compiling tests without running test bodies:

```sh
go test -count=1 -run '^$' ./...
```

Run vet, generated CLI documentation, build, and whitespace checks:

```sh
go vet ./...
make docs-check
make build
git diff --check
```

These commands are the default Phase 49 verification matrix. They must not use
live environment variables, optional live build tags, integration build tags,
worker daemon setup, provider API calls, network access, Docker, Podman,
Firecracker, or KVM.

Run `golangci-lint run ./...` only when `golangci-lint` is installed. If it is
unavailable, report lint unavailable instead of reporting lint as passed.

## Optional Live Gates

Optional live-provider paths are explicit opt-in only and are not part of
default Phase 49 verification:

| Optional path | Explicit opt-in gate | Default behavior without the gate |
| --- | --- | --- |
| Firecracker host/process live checks | explicit opt-in only: `firecracker_live` build tag plus `HAL_FIRECRACKER_LIVE=1` and Firecracker asset variables such as `HAL_FIRECRACKER_LIVE_FIRECRACKER`, `HAL_FIRECRACKER_LIVE_KERNEL`, and `HAL_FIRECRACKER_LIVE_ROOTFS` | Skipped or redaction-safe prerequisite diagnostics before any Firecracker process attempt |
| Network enforcement live checks | explicit opt-in only: `network_enforcement_live` build tag plus `HAL_NETWORK_ENFORCEMENT_LIVE=1`, `HAL_NETWORK_ENFORCEMENT_LIVE_PROXY=1`, and `HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL=1` | Skipped with sanitized missing-gate diagnostics before any listener, firewall, runtime-rule, or process mutation |
| Credential delivery live checks | explicit opt-in only: `credential_delivery_live` build tag plus `HAL_CREDENTIAL_DELIVERY_LIVE=1` and one credential delivery mode opt-in | Skipped with sanitized missing-gate diagnostics before any credential delivery attempt |
| Worker daemon integration checks | explicit opt-in only: `worker_integration` build tag plus the `HAL_WORKER_INTEGRATION_*` environment set | Skipped when worker integration configuration is incomplete; no default worker daemon attempt |
| Rootless Podman integration checks | explicit opt-in only: `podman_integration` build tag plus `HAL_PODMAN_TEST_IMAGE` and optional Podman path configuration | Skipped when Podman configuration is absent; no default Podman or Docker attempt |

Missing live configuration must skip optional live tests or report
redaction-safe diagnostics before any live-provider attempt. Default Phase 49
documentation and command examples must never promote those gates into the
fake-only matrix.

## Review Notes

Keep this document, `cmd/phase49_live_provider_gates_test.go`,
`cmd/default_fake_only_e2e_test.go`, and the optional live test files in sync
when live gate names, skip behavior, or default Phase 49 verification commands
change. Fake-only verification remains the default, and optional live-provider
coverage remains explicit opt-in only.
