# Sandbox Runtime v2 Phase 50 Manual Live Opt-In Verification

Phase 50 manual live opt-in commands are optional operator-run commands. They
are not part of default Phase 50 verification.

This document is a manual matrix for prepared hosts only. Every live command
requires both an optional Go build tag and explicit environment gates. Use
`<set>` placeholders in examples instead of real environment values.

Default Phase 50 verification remains fake-only. The live commands below are
not default checks, are not required for integration, and should be reported as
manual evidence only when an operator deliberately runs them.

Phase 50 verification excludes PRD regeneration, PRD audit, PRD validation, and
Hal workflow commands. Excluded Hal workflow commands include `hal validate`,
`hal convert --granular`, `hal plan`, `hal auto`, `hal run`, and `hal report`.

## Manual Command Matrix

| Category | Build tag | Environment gates | Manual command |
| --- | --- | --- | --- |
| Firecracker live host/process checks | `firecracker_live` | `HAL_FIRECRACKER_LIVE`, `HAL_FIRECRACKER_LIVE_FIRECRACKER`, `HAL_FIRECRACKER_LIVE_KERNEL`, `HAL_FIRECRACKER_LIVE_ROOTFS` | See Firecracker command below. |
| Network enforcement live checks | `network_enforcement_live` | `HAL_NETWORK_ENFORCEMENT_LIVE`, `HAL_NETWORK_ENFORCEMENT_LIVE_PROXY`, `HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL` | See network enforcement command below. |
| Credential delivery live checks | `credential_delivery_live` | `HAL_CREDENTIAL_DELIVERY_LIVE` plus one mode gate such as `HAL_CREDENTIAL_DELIVERY_LIVE_ENV` | See credential delivery command below. |
| Worker integration checks | `worker_integration` | `HAL_WORKER_INTEGRATION_ENDPOINT`, `HAL_WORKER_INTEGRATION_HOST_NAME`, `HAL_WORKER_INTEGRATION_RUNTIME_DRIVER`, `HAL_WORKER_INTEGRATION_IMAGE` | See worker command below. |
| Podman integration checks | `podman_integration` | `HAL_PODMAN_TEST_IMAGE`; `HAL_PODMAN_PATH` is optional when a non-default binary must be selected | See Podman command below. |

Run Firecracker live host/process checks only on a prepared host:

```sh
env HAL_FIRECRACKER_LIVE=<set> HAL_FIRECRACKER_LIVE_FIRECRACKER=<set> HAL_FIRECRACKER_LIVE_KERNEL=<set> HAL_FIRECRACKER_LIVE_ROOTFS=<set> go test -tags=firecracker_live -count=1 -timeout=120s ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost
```

Run network enforcement live checks only when proxy and firewall/runtime rule
prerequisites are deliberately enabled:

```sh
env HAL_NETWORK_ENFORCEMENT_LIVE=<set> HAL_NETWORK_ENFORCEMENT_LIVE_PROXY=<set> HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL=<set> go test -tags=network_enforcement_live -count=1 -timeout=120s ./internal/sandboxruntime/networkenforcement -run 'TestNetworkEnforcementLiveHarnessRequiresExplicitOptIn|TestNetworkEnforcementLivePrerequisiteSkipMessagesAreClearAndRedacted'
```

Run credential delivery live checks only when the global delivery gate and at
least one delivery-mode gate are deliberately enabled:

```sh
env HAL_CREDENTIAL_DELIVERY_LIVE=<set> HAL_CREDENTIAL_DELIVERY_LIVE_ENV=<set> go test -tags=credential_delivery_live -count=1 -timeout=120s ./internal/credentialdelivery -run 'TestCredentialDeliveryLiveHarnessRequiresExplicitOptIn|TestCredentialDeliveryLivePrerequisiteSkipMessagesAreSanitized|TestCredentialDeliveryLivePrerequisitesAcceptAnyModeGate'
```

Run worker integration checks only against an operator-provided worker daemon:

```sh
env HAL_WORKER_INTEGRATION_ENDPOINT=<set> HAL_WORKER_INTEGRATION_HOST_NAME=<set> HAL_WORKER_INTEGRATION_RUNTIME_DRIVER=<set> HAL_WORKER_INTEGRATION_IMAGE=<set> go test -tags=worker_integration -count=1 -timeout=120s ./cmd -run TestWorkerIntegrationRootlessPodmanExecutionThroughSharedResolver
```

Run Podman integration checks only when the image is already available to the
local rootless Podman installation:

```sh
env HAL_PODMAN_TEST_IMAGE=<set> go test -tags=podman_integration -count=1 -timeout=120s ./internal/sandboxruntime/rootlesspodman -run TestPodmanIntegrationLifecycleExecAndCopy
```

## Skip And Remediation Semantics

Missing prerequisites must produce a skip or remediation result before any live
action starts. Tests must skip before opening listeners, changing firewall or
runtime rules, launching Firecracker, starting worker-backed execution,
invoking Podman, delivering credentials, reading credential material, or
probing provider configuration.

Skip and remediation output may include gate IDs, build tags, env var names,
reason codes, and safe remediation commands. Allowed skip output fields are
gate IDs, category names, build tags, env var names, reason codes, capability
IDs, and remediation command templates that use `<set>` placeholders.

Skip and remediation output must not include env values, raw paths, hostnames,
URLs, socket paths, tokens, credentials, provider config, process args,
firewall details, or proxy details. Forbidden skip output fields are env
values, raw paths, hostnames, URLs, socket paths, tokens, credentials, provider
config, process args, firewall details, and proxy details.

## Review Notes

Keep this document, `cmd/phase50_manual_live_opt_in_docs_test.go`, the optional
live test files, and `internal/livegate` skip/remediation helpers in sync when
gate IDs, build tags, env var names, reason codes, or command templates change.
