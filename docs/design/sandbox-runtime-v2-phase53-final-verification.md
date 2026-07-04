# Sandbox Runtime v2 Phase 53 Final Verification

Phase 53 final verification barrier proves the live microVM E2E harness is safe
to merge after the metadata, diagnostics, live gates, preflight, network
readiness, credential delivery, template trust, live harness, marker guards, and
operator documentation stories have fanned in.

The default verification matrix is fake-only. It must not require Firecracker,
KVM, proxy or firewall readiness, credential delivery, template trust, live
environment markers, live build tags, Docker, Podman, provider APIs, network
listeners, firewall mutation, or sandbox daemon setup.

## Focused Checks

Run the Phase 53 command documentation, default-harness, and live-marker guards:

```sh
go test -count=1 ./cmd -run 'Test(US004|US010|Phase53)'
```

Run the default microVM live E2E contract, diagnostic, preflight, readiness,
credential, and template projection checks:

```sh
go test -count=1 ./internal/sandboxruntime/microvm -run 'Test(LiveE2E|MissingLiveE2E|MicroVMLiveE2E)'
```

## Broad Checks

Run the repository default test suite without live environment markers:

```sh
go test ./...
```

Run repository typecheck by compiling tests without running test bodies:

```sh
go test -count=1 -run '^$' ./...
```

Run vet, generated CLI documentation drift, build, and whitespace checks:

```sh
go vet ./...
make docs-check
make build
git diff --check
```

These commands are the required Phase 53 quality gates. `go test ./...` remains
fake-only and does not compile or execute the tagged live E2E path by default.

## Optional Live E2E

The live E2E command remains an operator-run diagnostic for prepared hosts only.
It is not part of the default quality gate matrix:

```sh
env HAL_FIRECRACKER_LIVE=<set> HAL_FIRECRACKER_LIVE_FIRECRACKER=<set> HAL_FIRECRACKER_LIVE_KERNEL=<set> HAL_FIRECRACKER_LIVE_ROOTFS=<set> HAL_NETWORK_ENFORCEMENT_LIVE=<set> HAL_NETWORK_ENFORCEMENT_LIVE_PROXY=<set> HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL=<set> HAL_CREDENTIAL_DELIVERY_LIVE=<set> HAL_CREDENTIAL_DELIVERY_LIVE_ENV=<set> HAL_TEMPLATE_TRUST_LIVE=<set> go test -tags=microvm_e2e_live,firecracker_live,network_enforcement_live,credential_delivery_live -count=1 -timeout=180s ./internal/sandboxruntime/microvm -run TestMicroVMLiveE2EComposedLiveExecutionPath
```

The live command is optional, tagged, and safe to skip when prerequisites are
missing. Missing Firecracker, KVM, proxy, firewall, credential delivery, env
delivery mode, or template trust prerequisites must produce sanitized skip
diagnostics before live execution starts.

## Non-Goals

Do not add live build tags, live environment markers, Firecracker boot, KVM
requirements, proxy listener startup, firewall mutation, real credential
delivery, template acquisition, Docker or Podman workflows, provider APIs,
network access, `hal sandboxd`, or Hal workflow commands to the default Phase 53
verification barrier.
