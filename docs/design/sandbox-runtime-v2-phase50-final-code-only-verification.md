# Sandbox Runtime v2 Phase 50 Final Code-Only Verification

Phase 50 final verification is code-only. It validates the live gate contract,
preflight evaluator, shared test helpers, fake-only default guards, manual
live opt-in documentation, and this final documentation barrier without product
workflow commands.

Default verification is fake-only. The default matrix uses focused live gate
contract, evaluator, helper, guard, documentation, and final barrier checks,
then repository-wide code checks. Manual live checks are optional operator
evidence only. Manual live checks are not part of default verification.

## Default Fake-Only Verification

Run the focused live gate contract, evaluator, helper, and import-boundary
checks:

```bash
go test -count=1 ./internal/livegate -run 'Test(GateCategoryConstantsAreStable|LiveGateContractConstantsAreStable|LiveGateJSON|EvaluateGate|GatePreflight|RequireLiveGate|LiveGate)'
```

Run the focused Phase 50 command-package guard, documentation, and final
barrier checks:

```bash
go test -count=1 ./cmd -run 'TestPhase50(Default|Optional|Manual|Final|Live|Guard)'
```

Run the default repository test suite:

```bash
go test ./...
```

Run repository typecheck by compiling tests without running test bodies:

```bash
go test -count=1 -run '^$' ./...
```

`go test -count=1 -run '^$' ./...` is the typecheck-only pass.

Run vet:

```bash
go vet ./...
```

Check gofmt output:

```bash
gofmt -l cmd internal main.go
```

Check whitespace:

```bash
git diff --check
```

Run lint only when `golangci-lint` is installed:

```bash
golangci-lint run ./...
```

`golangci-lint run ./...` is conditional. If `golangci-lint` is unavailable,
report `golangci-lint unavailable` in verification evidence instead of
claiming lint success.

## Optional Manual Live Verification

The commands below are separate manual checks for prepared hosts. They require
explicit build tags and environment gates, and they are not required for the
default matrix.

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

## Maintenance Notes

Keep this document, `cmd/phase50_final_code_only_verification_test.go`,
`cmd/phase50_manual_live_opt_in_docs_test.go`, and the live gate helper tests
in sync when Phase 50 guard selectors, optional manual live commands, or
conditional code checks change.
