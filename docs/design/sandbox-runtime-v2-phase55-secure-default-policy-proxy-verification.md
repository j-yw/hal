# Sandbox Runtime v2 Phase 55 Secure-Default Policy Proxy Verification

Phase 55 activates the worker-owned policy proxy proof path for secure-default
metadata without making it the production secure-default runtime. The phase
shows proxy-only progress truthfully: active proxy proof may appear as
`networkEnforcement=proxy`, while strict secure-default readiness remains
blocked until firewall or runtime rule proof also exists.

## Implemented Scope

`internal/sandboxruntime/networkenforcement` owns the policy proxy service
contracts, default-deny decision evaluation, unsafe destination blocking,
decision-log redaction, policy proxy lifecycle proof, and fake adapter
projection. It must stay independent of command packages, Cobra, concrete
runtime drivers, Docker or Podman SDKs, KVM or Firecracker SDKs, cloud SDKs,
and live firewall mutation dependencies.

`internal/sandboxworker` projects sanitized proxy-active proof into worker
status security metadata. It upgrades only to proxy-only enforcement when the
result is successful and the proxy lifecycle is active. It must not upgrade to
`proxy_firewall` without active firewall or runtime rule proof.

`cmd` remains a status and summary boundary. `hal sandbox runtime status
--json` consumes worker-projected runtime security, preserves proxy-only
partial enforcement as `networkEnforcement=proxy` with
`networkPolicy=best_effort`, keeps strict secure-default readiness blocked
when firewall or runtime rule proof is missing, and does not own proxy decision
behavior or expose raw `RuntimeNetworkEnforcementMetadata` proof fields.

## Non-Goals

Phase 55 does not add production firewall or runtime rule mutation, raw
TCP/UDP/ICMP enforcement, transparent guest egress routing, credential broker
delivery, templates or kits rollout, global default-on secure runtime
selection, Docker AI integration, hosted control planes, live KVM E2E, or
provider-backed live verification.

## Fake-Only Verification

Default Phase 55 verification is fake-only. It must not require root,
firewall mutation, Docker, Podman, KVM, Firecracker, cloud APIs, live network
egress, real proxy listener binding, real credentials, live worker daemons, or
optional live build tags.

Run network enforcement policy proxy contracts, lifecycle, redaction, and
import-boundary coverage:

```sh
go test -count=1 -timeout=180s ./internal/sandboxruntime/networkenforcement -run 'Test(PolicyProxy|NetworkEnforcement.*Import|NetworkEnforcementProductionImportsStayDataOnly)'
```

Run runtime metadata, worker projection, and microVM projection coverage:

```sh
go test -count=1 -timeout=180s ./internal/sandboxruntime ./internal/sandboxworker ./internal/sandboxruntime/microvm -run 'Test(RuntimeNetworkEnforcement|ServiceStatusProjectsProxyActiveNetworkEnforcementProof|ServiceStatusDoesNotUpgradeNetworkEnforcementWithoutActiveSuccessfulProxyProof|ServiceRuntimeDriverDescriptorProjectsNetworkSecurityFromActiveMetadataOnly|ServiceMicroVMCapabilityOutputDoesNotClaimDefaultNetworkEnforcement|MicroVMNetworkEnforcement)'
```

Run command status JSON projection and command-boundary guards:

```sh
go test -count=1 -timeout=180s ./cmd -run 'Test(US012SandboxRuntimeStatusJSON|Phase55Command|CommandAndSandboxdProductionSecurityPathsAvoidLiveMutationDependencies|SandboxdProductionCodeDoesNotOwnNetworkEnforcementPlanningOrSetup)'
```

Run the full fake-only barrier:

```sh
go test ./...
go vet ./...
make docs-check
make build
git diff --check
```

Optional live/probing tests remain outside this phase. If a later phase adds
or changes live checks, they must require explicit build tags and environment
markers and must not become part of default Phase 55 verification.
