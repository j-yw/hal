# Sandbox Runtime v2 Phase 54 Release Package Verification

Phase 54 US-002 guards the release build and package command surface for this
branch. Phase 54 US-003 defines the default fake-only CI matrix for routine
verification on ordinary developer and CI hosts. The branch build artifact is
the Hal CLI binary, produced locally as `./hal`.

## Default CI Matrix

Default CI is fake-only. It must not require live runtime prerequisites such as
Firecracker, KVM, Docker/Podman, sandboxd, cloud provider access, registry
credentials, proxy listeners, firewall mutation, real API secrets, live
environment markers, or tagged live test suites.

The default matrix is:

```sh
go test ./...
go vet ./...
make docs-check
make build
git diff --check
```

These commands validate tests, vet, generated CLI documentation drift, the local
Hal binary build, and whitespace. Optional live suites stay outside default CI
and must be documented as explicit opt-in operator checks.

Phase 54 planning workflow references use plain `hal convert`; they do not
require `hal convert --granular`.

## Optional Live Verification Matrix

These commands are optional operator-run checks for prepared live
infrastructure. They are not default CI, not release package prerequisites, and
not post-run PRD validation. Keep marker names as names only; use `<set>`
placeholders in command examples and do not record environment values, host
paths, socket paths, provider handles, ports, URLs, credentials, tokens, or
machine-specific command arguments in verification notes.

Run the focused live-gate and live-marker guard suite without live tags or live
environment markers:

```sh
go test -count=1 -timeout=180s ./internal/livegate ./cmd -run 'Test(LiveGate|RequireLiveGate|MicroVME2ELiveGate|Phase50.*Live|US003MicroVMLiveE2E|US010.*Live)'
```

Run Firecracker host/process and microVM live checks only on a prepared host:

```sh
env HAL_FIRECRACKER_LIVE=<set> HAL_FIRECRACKER_LIVE_FIRECRACKER=<set> HAL_FIRECRACKER_LIVE_KERNEL=<set> HAL_FIRECRACKER_LIVE_ROOTFS=<set> go test -tags=firecracker_live -count=1 -timeout=120s ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost
```

Firecracker/microVM live tag names discovered in the repository:

- `firecracker_live`
- `microvm_e2e_live`

Firecracker/microVM marker names discovered in the repository:

- `HAL_FIRECRACKER_LIVE`
- `HAL_FIRECRACKER_LIVE_FIRECRACKER`
- `HAL_FIRECRACKER_LIVE_KERNEL`
- `HAL_FIRECRACKER_LIVE_ROOTFS`
- `HAL_FIRECRACKER_LIVE_INITRD`
- `HAL_FIRECRACKER_LIVE_TIMEOUT`
- `HAL_FIRECRACKER_LIVE_CPU_COUNT`
- `HAL_FIRECRACKER_LIVE_MEMORY_MIB`

Run network enforcement live checks only when proxy and firewall/runtime-rule
prerequisites are deliberately enabled:

```sh
env HAL_NETWORK_ENFORCEMENT_LIVE=<set> HAL_NETWORK_ENFORCEMENT_LIVE_PROXY=<set> HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL=<set> go test -tags=network_enforcement_live -count=1 -timeout=120s ./internal/sandboxruntime/networkenforcement -run 'TestNetworkEnforcementLiveHarnessRequiresExplicitOptIn|TestNetworkEnforcementLivePrerequisiteSkipMessagesAreClearAndRedacted'
```

Network enforcement live tag and marker names discovered in the repository:

- `network_enforcement_live`
- `HAL_NETWORK_ENFORCEMENT_LIVE`
- `HAL_NETWORK_ENFORCEMENT_LIVE_PROXY`
- `HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL`

Run credential delivery live checks only when the global delivery gate and at
least one delivery-mode gate are deliberately enabled:

```sh
env HAL_CREDENTIAL_DELIVERY_LIVE=<set> HAL_CREDENTIAL_DELIVERY_LIVE_ENV=<set> go test -tags=credential_delivery_live -count=1 -timeout=120s ./internal/credentialdelivery -run 'TestCredentialDeliveryLiveHarnessRequiresExplicitOptIn|TestCredentialDeliveryLivePrerequisiteSkipMessagesAreSanitized|TestCredentialDeliveryLivePrerequisitesAcceptAnyModeGate'
```

Credential delivery live tag and marker names discovered in the repository:

- `credential_delivery_live`
- `HAL_CREDENTIAL_DELIVERY_LIVE`
- `HAL_CREDENTIAL_DELIVERY_LIVE_HTTP_PROXY`
- `HAL_CREDENTIAL_DELIVERY_LIVE_FILE_TMPFS`
- `HAL_CREDENTIAL_DELIVERY_LIVE_SSH_AGENT`
- `HAL_CREDENTIAL_DELIVERY_LIVE_ENV`

Run the template provenance and trust-policy suite as fake/local verification:

```sh
go test -count=1 -timeout=180s ./internal/sandboxtemplate/acquisition -run 'Test(TrustPolicy|EvaluateTrustPolicy|ProjectTemplateProvenance|ProjectRuntimeTemplateLockMetadata|SandboxTemplateAcquisitionImportBoundaryAllowsTrustPolicyRuntimeMetadataProjection)'
```

```sh
go test -count=1 -timeout=180s ./cmd -run 'TestPhase52Template'
```

No standalone template/provenance live build tag is present. The live template
trust marker discovered in the repository is `HAL_TEMPLATE_TRUST_LIVE`; it is
exercised by the composed microVM live E2E command below.

Run the composed Firecracker, network enforcement, credential delivery, and
template trust live E2E only on a host prepared for every listed gate:

```sh
env HAL_FIRECRACKER_LIVE=<set> HAL_FIRECRACKER_LIVE_FIRECRACKER=<set> HAL_FIRECRACKER_LIVE_KERNEL=<set> HAL_FIRECRACKER_LIVE_ROOTFS=<set> HAL_NETWORK_ENFORCEMENT_LIVE=<set> HAL_NETWORK_ENFORCEMENT_LIVE_PROXY=<set> HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL=<set> HAL_CREDENTIAL_DELIVERY_LIVE=<set> HAL_CREDENTIAL_DELIVERY_LIVE_ENV=<set> HAL_TEMPLATE_TRUST_LIVE=<set> go test -tags=microvm_e2e_live,firecracker_live,network_enforcement_live,credential_delivery_live -count=1 -timeout=180s ./internal/sandboxruntime/microvm -run TestMicroVMLiveE2EComposedLiveExecutionPath
```

When required build tags are absent, Go excludes the tagged live test files
from default package builds. When required environment markers are absent, live
gate tests skip with sanitized missing-prerequisite messages before
Firecracker launch, listener or firewall mutation, credential delivery,
template trust live execution, provider probing, or any runtime state change.
The standalone network enforcement and credential delivery live harnesses
currently remain opt-in placeholders after their gates are satisfied; the
composed microVM live E2E command is the only documented live execution path.

## Expected Build Command

Use the Makefile build target as the release build command:

```sh
make build
```

The target compiles the root module with version metadata and writes the Hal
binary to `./hal`.

For a local package configuration check, use the GoReleaser validation target
when GoReleaser is installed:

```sh
make release-check
```

`make release-check` is config validation only. It must not publish releases or
read release credentials.

## Guarded Surface

The guarded default package/build path is limited to local Go compilation and
configuration validation. It must stay free of root privilege setup, KVM,
Firecracker, Docker/Podman, sandboxd, cloud provider access, registry
credentials, proxy listeners, firewall mutation, and real API secrets.

Tag-triggered publishing, Homebrew tap updates, sandbox image builds, optional
live suites, and operator-run live diagnostics are outside this default
package/build guard.

## Focused Guard

Run the Phase 54 command-surface guard:

```sh
go test -count=1 ./cmd -run TestPhase54
```

Then run the documented release build command:

```sh
make build
```

The expected binary surface is `./hal`; a quick local smoke check is:

```sh
./hal version
```
