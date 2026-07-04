# Sandbox Runtime v2 Phase 53 Live E2E Verification

Phase 53 adds one narrow operator-run live E2E command for prepared hosts. The
command is outside default verification and runs only with the dedicated
`microvm_e2e_live` build tag plus the existing Firecracker, network
enforcement, and credential delivery live tags.

Exact package selector: `./internal/sandboxruntime/microvm`.

## Required Opt-In Markers

Required build tags:

- `microvm_e2e_live`
- `firecracker_live`
- `network_enforcement_live`
- `credential_delivery_live`

Required environment marker names:

- `HAL_FIRECRACKER_LIVE`
- `HAL_FIRECRACKER_LIVE_FIRECRACKER`
- `HAL_FIRECRACKER_LIVE_KERNEL`
- `HAL_FIRECRACKER_LIVE_ROOTFS`
- `HAL_NETWORK_ENFORCEMENT_LIVE`
- `HAL_NETWORK_ENFORCEMENT_LIVE_PROXY`
- `HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL`
- `HAL_CREDENTIAL_DELIVERY_LIVE`
- `HAL_CREDENTIAL_DELIVERY_LIVE_ENV`
- `HAL_TEMPLATE_TRUST_LIVE`

The marker list is intentionally names-only. The documentation must not provide
example secret values, credential material, absolute host paths, socket paths,
provider config, proxy endpoints, firewall rules, or Firecracker command-line
arguments.

## Live Command

```sh
env HAL_FIRECRACKER_LIVE=<set> HAL_FIRECRACKER_LIVE_FIRECRACKER=<set> HAL_FIRECRACKER_LIVE_KERNEL=<set> HAL_FIRECRACKER_LIVE_ROOTFS=<set> HAL_NETWORK_ENFORCEMENT_LIVE=<set> HAL_NETWORK_ENFORCEMENT_LIVE_PROXY=<set> HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL=<set> HAL_CREDENTIAL_DELIVERY_LIVE=<set> HAL_CREDENTIAL_DELIVERY_LIVE_ENV=<set> HAL_TEMPLATE_TRUST_LIVE=<set> go test -tags=microvm_e2e_live,firecracker_live,network_enforcement_live,credential_delivery_live -count=1 -timeout=180s ./internal/sandboxruntime/microvm -run TestMicroVMLiveE2EComposedLiveExecutionPath
```

The test composes the shared live gate, Firecracker microVM preflight, network proxy and firewall readiness metadata, credential delivery activation metadata, and template trust metadata before the Firecracker live driver creates or starts a target.

## Skip And Failure Semantics

Missing build tags, marker variables, Firecracker launch assets, KVM host
capability, network proxy readiness, firewall readiness, credential delivery
activation, credential mode selection, env-delivery marker, or template trust
metadata produce sanitized skips before live execution starts.

Explicit readiness claims that do not prove active proxy plus active firewall under a `proxy_firewall` default-deny result fail with sanitized diagnostics.
Failure output uses safe component names, statuses, reason codes, and
prerequisite names only.

The command output must not include environment values, raw host paths,
hostnames, URLs, socket paths, process handles, firewall rules, proxy listener
details, credentials, tokens, provider config, or command arguments.

## Default Verification Boundary

`go test ./...` remains fake-only. It must not require Firecracker, KVM, proxy,
firewall, credential delivery, template trust, live build tags, or live
environment markers.

This live E2E command is an explicit operator diagnostic for prepared live
hosts. It must not be used as post-run PRD validation.
