# Sandbox Runtime v2 Phase 54 Operator Release Handoff

Phase 54 is the final release-operator handoff for the Sandbox Runtime v2
production-hardening wave. It fans in the completed package, default CI, and
optional live verification work for this branch before opening or merging a PR.

## Completed Wave Summary

- US-001 locked the release scope: Phase 54 does not expand status, doctor,
  continue, sandbox manifest, factory, or runtime JSON contracts just to ship
  the release verification pass.
- US-002 documented and guarded the release package surface. The local release
  build artifact is the Hal CLI binary at `./hal`, produced by `make build`.
- US-003 defined the default CI matrix as deterministic and fake-only for
  ordinary developer and CI hosts.
- US-004 separated optional live verification from default CI and documented
  the exact opt-in live tags, environment marker names, and safe placeholder
  command lines.

Use `docs/design/sandbox-runtime-v2-phase54-release-package-verification.md`
for the package and matrix details. Use
`docs/design/sandbox-runtime-v2-phase53-final-verification.md` for the Phase 53
live E2E background that the composed Phase 54 optional command reuses.

## Default Verification Commands

Run these before opening the PR and again before merging after review changes:

```sh
go test ./...
go vet ./...
make docs-check
make build
git diff --check
```

Run the focused Phase 54 handoff and release documentation guards when editing
this document or the Phase 54 release verification document:

```sh
go test -count=1 ./cmd -run TestPhase54OperatorReleaseHandoff
go test -count=1 ./cmd -run TestPhase54
```

The default verification path is fake-only. It must not require root, KVM,
Firecracker, Docker/Podman, sandboxd, cloud provider access, registry
credentials, proxy listeners, firewall mutation, real API secrets, live
environment markers, or tagged live suites.

## Optional Live Verification Commands

These commands are manual operator checks for prepared live infrastructure.
They are not part of default CI, package verification, or the required
pre-merge gate.

Run the focused live-gate and live-marker guard suite:

```sh
go test -count=1 -timeout=180s ./internal/livegate ./cmd -run 'Test(LiveGate|RequireLiveGate|MicroVME2ELiveGate|Phase50.*Live|US003MicroVMLiveE2E|US010.*Live)'
```

Run Firecracker host/process and microVM live checks:

```sh
env HAL_FIRECRACKER_LIVE=<set> HAL_FIRECRACKER_LIVE_FIRECRACKER=<set> HAL_FIRECRACKER_LIVE_KERNEL=<set> HAL_FIRECRACKER_LIVE_ROOTFS=<set> go test -tags=firecracker_live -count=1 -timeout=120s ./internal/sandboxruntime/microvm/firecracker ./internal/sandboxruntime/microvm/firecrackerhost
```

Run network enforcement live checks:

```sh
env HAL_NETWORK_ENFORCEMENT_LIVE=<set> HAL_NETWORK_ENFORCEMENT_LIVE_PROXY=<set> HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL=<set> go test -tags=network_enforcement_live -count=1 -timeout=120s ./internal/sandboxruntime/networkenforcement -run 'TestNetworkEnforcementLiveHarnessRequiresExplicitOptIn|TestNetworkEnforcementLivePrerequisiteSkipMessagesAreClearAndRedacted'
```

Run credential delivery live checks:

```sh
env HAL_CREDENTIAL_DELIVERY_LIVE=<set> HAL_CREDENTIAL_DELIVERY_LIVE_ENV=<set> go test -tags=credential_delivery_live -count=1 -timeout=120s ./internal/credentialdelivery -run 'TestCredentialDeliveryLiveHarnessRequiresExplicitOptIn|TestCredentialDeliveryLivePrerequisiteSkipMessagesAreSanitized|TestCredentialDeliveryLivePrerequisitesAcceptAnyModeGate'
```

Run template provenance and trust-policy fake/local checks:

```sh
go test -count=1 -timeout=180s ./internal/sandboxtemplate/acquisition -run 'Test(TrustPolicy|EvaluateTrustPolicy|ProjectTemplateProvenance|ProjectRuntimeTemplateLockMetadata|SandboxTemplateAcquisitionImportBoundaryAllowsTrustPolicyRuntimeMetadataProjection)'
```

```sh
go test -count=1 -timeout=180s ./cmd -run 'TestPhase52Template'
```

Run the composed Firecracker, network enforcement, credential delivery, and
template trust live E2E only on a host prepared for every listed gate:

```sh
env HAL_FIRECRACKER_LIVE=<set> HAL_FIRECRACKER_LIVE_FIRECRACKER=<set> HAL_FIRECRACKER_LIVE_KERNEL=<set> HAL_FIRECRACKER_LIVE_ROOTFS=<set> HAL_NETWORK_ENFORCEMENT_LIVE=<set> HAL_NETWORK_ENFORCEMENT_LIVE_PROXY=<set> HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL=<set> HAL_CREDENTIAL_DELIVERY_LIVE=<set> HAL_CREDENTIAL_DELIVERY_LIVE_ENV=<set> HAL_TEMPLATE_TRUST_LIVE=<set> go test -tags=microvm_e2e_live,firecracker_live,network_enforcement_live,credential_delivery_live -count=1 -timeout=180s ./internal/sandboxruntime/microvm -run TestMicroVMLiveE2EComposedLiveExecutionPath
```

## Optional Live Skip Behavior

When required build tags are absent, Go excludes tagged live test files from
default package builds. When required environment markers are absent, live gate
tests skip with sanitized missing-prerequisite messages before Firecracker
launch, listener or firewall mutation, credential delivery, template trust live
execution, provider probing, or any runtime state change.

The standalone network enforcement and credential delivery live harnesses
currently remain opt-in placeholders after their gates are satisfied. The
composed microVM live E2E command is the only documented live execution path.

## Not Enabled By Default

Phase 54 intentionally does not enable these by default:

- live Firecracker or microVM boot verification, KVM access, Docker/Podman,
  sandboxd, live worker daemons, cloud provider probing, registry access,
  proxy listener startup, firewall mutation, or real credential delivery;
- default-on network proxy/firewall enforcement in routine CI or packaging;
- credential broker delivery as default agent behavior;
- template/kits provenance, acquisition, or trust-policy behavior as a
  production default;
- sandbox image builds, tag-triggered release publishing, or Homebrew tap
  updates from the local verification path.

## Production Secure-Default Gap Audit

The remaining secure-default work is future work after Phase 54:

- Default-on network proxy/firewall enforcement is not complete unless a
  runtime actually enforces it. Requested policy metadata, readiness
  projection, or live-gate documentation alone is not runtime enforcement.
- Credential broker delivery as default agent behavior still needs production
  hardening beyond metadata/projection before it can be treated as a default
  agent path.
- Template/kits provenance and trust policy exist, but operational production
  defaulting still needs rollout decisions for which kits are trusted, how
  policy updates are governed, and when operators deliberately enable them.
- Release/CI must not claim deny-by-default network security merely because
  requested metadata exists. A deny-by-default claim requires runtime evidence
  from the selected runtime path.
- This is multi-day future work and should be split into a new wave after Phase
  54 rather than hidden in the final packaging and CI handoff.

## Pre-PR And Pre-Merge Checklist

- Confirm the branch is
  `hal/prod-54-final-packaging-ci-release-verification` or a worker branch that
  targets it.
- Confirm `.hal/prd.json` and `.hal/progress.txt` were not hand-edited by the
  worker task.
- Run the default verification commands and keep the output available for the
  PR description.
- Run the focused Phase 54 guard command after editing Phase 54 docs or release
  guard tests.
- Decide explicitly whether optional live checks are in scope for the PR. If
  skipped, record that they were skipped because they are manual prepared-host
  diagnostics, not default CI.
- If optional live checks are run, record only build tag names, environment
  marker names, commands, pass or skip status, and sanitized diagnostics. Do not
  record environment values, host paths, socket paths, URLs, ports, provider
  handles, tokens, credentials, or machine-specific command arguments.
- Smoke check the built CLI with `./hal version` after `make build`.
- Re-run `git diff --check` after any final documentation or manifest edit.
