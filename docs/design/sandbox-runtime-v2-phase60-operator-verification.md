# Sandbox Runtime v2 Phase 60 Operator Verification

Phase 60 validates the secure-default sandbox runtime path with fake-only
release gates by default and separate optional live diagnostics for prepared
hosts. The release gate is executable code verification: tests, typecheck,
vet, docs drift, build, and whitespace checks. It is not PRD post-run
validation, PRD conversion, PRD regeneration, or Hal workflow state review.

The secure-default invariant for this phase is fail-closed. Strict
secure-default acceptance requires complete sanitized proof for target
selection, MicroVM isolation, deny-by-default network enforcement, credential
delivery, selected-template trust, and command/status projection. Missing,
partial, warning-bearing, compatibility-only, metadata-only, or advisory proof
must remain a blocked or skipped outcome and must not be rendered as accepted
secure-default readiness.

## Default Fake-Only Verification

Default Phase 60 verification is fake-only. It must not require root, KVM,
Firecracker, firewall mutation, proxy listeners, credential delivery adapters,
template registries, sandboxd, Docker, Podman, cloud provider access, live
worker daemons, live build tags, live environment marker values, or network
egress.

Run the complete fake-only release-gate command set:

```sh
go test ./...
go test -count=1 -run '^$' ./...
go vet ./...
make docs-check
make build
git diff --check
```

`go test -count=1 -run '^$' ./...` is the typecheck-only pass. Run
`golangci-lint run ./...` only when `golangci-lint` is installed; if it is
unavailable, report lint unavailable instead of reporting lint as passed.

Default verification evidence must come from the commands above or narrower
fake-only commands that are rerun before the full gate. Do not treat
`.hal/prd.json`, `.hal/progress.txt`, `hal validate`, `hal convert`, `hal run`,
`hal auto`, `hal report`, or other PRD/workflow post-run checks as final
release acceptance evidence for Phase 60.

## Optional Live Prepared-Host Checks

Optional live checks are operator-run diagnostics for intentionally prepared
hosts only. They are outside the default fake-only release gate and must be
recorded separately. Run them only after the operator has provided the required
marker names in the environment for the selected command. This document names
markers only; it intentionally does not show marker values, assignment syntax,
host paths, socket paths, URLs, ports, provider handles, credentials, tokens,
or machine-specific arguments.

Run standalone Firecracker live checks only on a host prepared for Firecracker
and KVM:

```sh
go test -tags=firecracker_live -count=1 -timeout=120s ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost
```

Run standalone network enforcement live checks only on a host prepared for the
network proof gates:

```sh
go test -tags=network_enforcement_live -count=1 -timeout=120s ./internal/sandboxruntime/networkenforcement -run 'TestNetworkEnforcementLiveHarnessRequiresExplicitOptIn|TestNetworkEnforcementLivePrerequisiteSkipMessagesAreClearAndRedacted'
```

Run standalone credential delivery live checks only on a host prepared for the
global credential delivery gate and at least one delivery mode gate:

```sh
go test -tags=credential_delivery_live -count=1 -timeout=120s ./internal/credentialdelivery -run 'TestCredentialDeliveryLiveHarnessRequiresExplicitOptIn|TestCredentialDeliveryLivePrerequisiteSkipMessagesAreSanitized|TestCredentialDeliveryLivePrerequisitesAcceptAnyModeGate'
```

Run the composed prepared-host microVM live E2E check only when all component
gates are deliberately enabled and the host is prepared for Firecracker, KVM,
network enforcement, credential delivery, and selected-template trust:

```sh
go test -tags=microvm_e2e_live,firecracker_live,network_enforcement_live,credential_delivery_live -count=1 -timeout=180s ./internal/sandboxruntime/microvm -run TestMicroVMLiveE2EComposedLiveExecutionPath
```

## Live Marker Names

Prepared-host live checks use these build tags:

- `firecracker_live`
- `network_enforcement_live`
- `credential_delivery_live`
- `microvm_e2e_live`

The composed microVM live E2E gate requires these environment marker names:

- `HAL_FIRECRACKER_LIVE`
- `HAL_FIRECRACKER_LIVE_FIRECRACKER`
- `HAL_FIRECRACKER_LIVE_KERNEL`
- `HAL_FIRECRACKER_LIVE_ROOTFS`
- `HAL_NETWORK_ENFORCEMENT_LIVE`
- `HAL_NETWORK_ENFORCEMENT_LIVE_PROXY`
- `HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL`
- `HAL_CREDENTIAL_DELIVERY_LIVE`
- `HAL_TEMPLATE_TRUST_LIVE`

The separately selected L7 Firecracker network-image prerequisite check also
uses this marker name:

- `HAL_L7_DISTRIBUTION_DIR`

Standalone Firecracker checks also recognize these optional Firecracker marker
names:

- `HAL_FIRECRACKER_LIVE_INITRD`
- `HAL_FIRECRACKER_LIVE_TIMEOUT`
- `HAL_FIRECRACKER_LIVE_CPU_COUNT`
- `HAL_FIRECRACKER_LIVE_MEMORY_MIB`

Credential delivery also requires at least one delivery mode marker name:

- `HAL_CREDENTIAL_DELIVERY_LIVE_HTTP_PROXY`
- `HAL_CREDENTIAL_DELIVERY_LIVE_FILE_TMPFS`
- `HAL_CREDENTIAL_DELIVERY_LIVE_SSH_AGENT`
- `HAL_CREDENTIAL_DELIVERY_LIVE_ENV`

Standalone Firecracker checks use the Firecracker marker names. Standalone
network enforcement checks use the network enforcement marker names.
Standalone credential delivery checks use the global credential marker name and
at least one delivery mode marker name. Verification records may say a marker
name was present, absent, or skipped; they must not record marker values.

## Skip Semantics

When required build tags are absent, Go excludes tagged live test files from
default package builds. When required marker names are absent, live gate tests
must skip before Firecracker launch, process execution, KVM access, listener
binding, firewall or runtime rule mutation, credential delivery, template trust
live execution, provider probing, worker daemon use, sandboxd use, cleanup of
live state, or network egress.

Missing KVM, Firecracker, root privileges, firewall capability, proxy
capability, sandboxd, credentials, registry access, credential delivery mode,
template trust, prepared images, or other host prerequisites are sanitized skip
outcomes for optional live checks. Skip messages may name marker names,
prerequisite labels, safe reason codes, and high-level capability categories
only.

## Failure Semantics

Missing or partial secure-default proof is a failure for strict acceptance, not
a reason to downgrade silently into an accepted secure-default claim. The
strict gate must fail closed when any required proof source is absent,
inactive, partial, metadata-only, compatibility-only, advisory-only,
warning-bearing, failed, uncorrelated, or unsanitized.

Optional live checks may skip when prerequisites are missing before live work
begins. Once a prepared-host check proceeds past its gates, incomplete
secure-default evidence such as proxy-only network proof, firewall-only network
proof, missing MicroVM isolation proof, missing credential activation proof,
missing selected-template digest trust, or raw unsafe metadata must be reported
as a sanitized failure or blocked readiness decision. It must not be recorded
as accepted strict secure-default readiness.

## Operator Record

For Phase 60 release decisions, record the default fake-only command results
and any optional live checks separately. A skipped optional live command should
be recorded as skipped with a sanitized prerequisite reason. Final Phase 60
acceptance must be based on code verification commands, not PRD post-run
validation.

## Final Code Verification Record

US-018 recorded final code verification on 2026-07-04 UTC.

Default code verification results:

- `go test ./...`: passed.
- `go test -count=1 -run '^$' ./...`: passed.
- `go vet ./...`: passed.
- `make docs-check`: passed.
- `make build`: passed.
- `git diff --check`: passed.

Skipped prepared-host diagnostics:

- `go test -tags=firecracker_live -count=1 -timeout=120s ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost`: skipped; sanitized prerequisite reason: prepared-host live markers were not provided.
- `go test -tags=network_enforcement_live -count=1 -timeout=120s ./internal/sandboxruntime/networkenforcement -run 'TestNetworkEnforcementLiveHarnessRequiresExplicitOptIn|TestNetworkEnforcementLivePrerequisiteSkipMessagesAreClearAndRedacted'`: skipped; sanitized prerequisite reason: prepared-host live markers were not provided.
- `go test -tags=credential_delivery_live -count=1 -timeout=120s ./internal/credentialdelivery -run 'TestCredentialDeliveryLiveHarnessRequiresExplicitOptIn|TestCredentialDeliveryLivePrerequisiteSkipMessagesAreSanitized|TestCredentialDeliveryLivePrerequisitesAcceptAnyModeGate'`: skipped; sanitized prerequisite reason: prepared-host live markers were not provided.
- `go test -tags=microvm_e2e_live,firecracker_live,network_enforcement_live,credential_delivery_live -count=1 -timeout=180s ./internal/sandboxruntime/microvm -run TestMicroVMLiveE2EComposedLiveExecutionPath`: skipped; sanitized prerequisite reason: prepared-host live markers were not provided.

Final acceptance: accepted from the recorded code verification commands above;
PRD post-run validation was not used.
