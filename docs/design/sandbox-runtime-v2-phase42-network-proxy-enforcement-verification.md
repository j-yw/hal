# Sandbox Runtime v2 Phase 42 Network Proxy Enforcement Verification

Phase 42 adds a fake-safe network proxy enforcement planning layer for sandbox
runtime metadata, worker capability projection, sandboxd microVM registration,
and microVM runtime metadata. The phase makes requested network posture
testable and redaction-safe without adding live proxy listeners, firewall
mutation, credential injection, or production microVM egress.

## Implemented Scope

`internal/sandboxruntime/networkenforcement` owns the runtime-owned network
enforcement plan, planner, adapter, result, fake adapter test harness, and
import-boundary guards. Plans represent deny-by-default posture, allowlist
policy categories, private-network and metadata-endpoint blocking, raw
TCP/UDP/ICMP posture, HTTP/HTTPS proxy routing intent, and firewall intent
using safe identifiers, enum-like values, operation labels, and policy snapshot
identity only. Public plan and result JSON is sanitized before it reaches
runtime metadata, worker capability metadata, or tests.

`internal/sandbox` keeps requested-versus-enforced security honest. Explicit
ready metadata can report network proxy or firewall capability, but metadata
only hints, legacy compatibility policy, worker posture, proxy session
metadata, and failed adapter results do not become enforced deny-by-default
claims.

`internal/sandboxruntime` projects optional network enforcement plan and result
metadata through `RuntimeMetadata.networkEnforcement`. Sanitizers preserve only
safe plan/result labels, clear unsafe values, and remove capability upgrades on
failure or unsupported outcomes.

`internal/sandboxworker` can include explicit sanitized network enforcement
capability in worker and runtime-driver capability output. Unconfigured worker
and microVM capability output stays metadata-only and does not claim default
network enforcement.

`internal/sandboxruntime/microvm` accepts explicit
`NetworkEnforcementPlanning` options. The microVM driver calls the injected
planner and adapter only when that explicit planning value is configured,
projects sanitized plan/result metadata, and fails closed to unsupported
metadata when no adapter is available. Default microVM construction leaves
network enforcement metadata absent.

`internal/sandboxruntime/microvm/firecrackerhost` passes explicit network
enforcement planning to the microVM driver through the existing live-driver
option boundary. Phase 42 does not add Firecracker SDK calls, network device
configuration, guest egress setup, or host firewall work.

`cmd/sandboxd.go` does not own network policy parsing, proxy setup, firewall
setup, or live listener logic. Sandboxd registration requests a network plan
only through explicit microVM runtime configuration and keeps rootless-only
registration inert.

## Verification Commands

Run network enforcement contract, planner, adapter, fake adapter, redaction,
and import-boundary coverage:

```sh
go test -count=1 -timeout=180s ./internal/sandboxruntime/networkenforcement
```

Run sandbox security-readiness and runtime metadata projection coverage:

```sh
go test -count=1 -timeout=180s ./internal/sandbox ./internal/sandboxruntime
```

Run worker capability and security-policy coverage:

```sh
go test -count=1 -timeout=180s ./internal/sandboxworker
```

Run microVM planning and Firecracker host handoff coverage:

```sh
go test -count=1 -timeout=180s ./internal/sandboxruntime/microvm ./internal/sandboxruntime/microvm/firecrackerhost
```

Run command-level sandboxd, sandbox host mapping, documentation, and source
guard coverage:

```sh
go test -count=1 -timeout=180s ./cmd -run 'Phase4[2].*Network|NetworkEnforcement|Sandboxd.*Network|SandboxHost.*Network'
```

Run the full repository verification stack:

```sh
go test -count=1 -timeout=420s ./...
go test -count=1 -timeout=300s -run '^$' ./...
go vet ./...
make docs-check
make build
git diff --check
```

Run `golangci-lint run ./...` only when `golangci-lint` is installed. If it is
unavailable, report lint unavailable instead of reporting lint as passed.

Passing this matrix satisfies the Phase 42 tests and typecheck gates.

## Fake-Only Scope

Phase 42 verification is fake-only. It does not require real network access,
live proxy listeners, bound sockets, firewall mutation, credential delivery,
credential injection, tmpfs secret writes, SSH-agent forwarding, Docker,
Podman, KVM, a Firecracker binary, root privileges, cloud credentials, worker
daemons, provider/runtime integration, a live guest, a guest agent, vsock, or
a running `hal sandboxd`.

Default Phase 42 tests use pure DTOs, deterministic planner inputs, sanitized
public JSON assertions, fake adapter implementations, injected planner and
adapter boundaries, fake command dependencies, parsed imports, source guards,
temporary state directories, and explicit metadata only.

Default Phase 42 verification must not use integration build tags, the
`firecracker_live` build tag, require live environment variables, start a real
proxy, bind listener sockets, mutate firewall rules, inject credentials, start
a real Firecracker process, access KVM, require root, start worker daemons, run
`hal sandboxd`, call Docker or Podman, contact cloud APIs, invoke Firecracker
SDKs, or depend on live providers or runtime adapters.

## Focused Test Inventory

Sandbox package coverage:

- `TestEvaluateSecurityCapabilityReadinessMarksRequestedStrictNetworkEnforcementUnsupportedWithoutSupport`
- `TestEvaluateSecurityCapabilityReadinessMarksExplicitReadyNetworkEnforcement`
- `TestEvaluateSecurityCapabilityReadinessDoesNotInferReadyFromLegacyCompatibilityMetadata`
- `TestEvaluateSecurityCapabilityReadinessTreatsWorkerPostureCapabilitiesAsMetadataOnly`
- `TestEffectiveNetworkPolicyCompatibility`

Sandboxruntime package coverage:

- `TestPlanJSONRepresentsRequiredNetworkPosture`
- `TestPlanJSONRedactsUnsafeDynamicValues`
- `TestPlanJSONDropsUnsafePolicySnapshotAndProxySessionIdentifiers`
- `TestBuildPlanConstructsDefaultDenyPrivateAndMetadataPosture`
- `TestNormalizeAllowlistRulesSupportsSafeRuleCategories`
- `TestBuildPlanNormalizesAllowlistRulesWithoutExposingRawValues`
- `TestNormalizeAllowlistRulesRejectsUnsafeValuesWithSanitizedErrors`
- `TestRunAdapterPassesSanitizedPlanAndReturnsSanitizedResult`
- `TestRunAdapterNilAdapterReportsUnsupported`
- `TestFakeEnforcementAdapterSuccessCanClaimStrongerCapability`
- `TestFakeEnforcementAdapterFailureFailsClosed`
- `TestFakeEnforcementAdapterErrorSurfacesAreRedacted`
- `TestNetworkEnforcementProductionImportsStayDataOnly`
- `TestRuntimeMetadataIncludesOptionalNetworkEnforcementMetadata`
- `TestRuntimeNetworkEnforcementMetadataSanitizesUnsafeValues`
- `TestRuntimeNetworkEnforcementFailureClearsCapabilityUpgrade`
- `TestSandboxruntimeNetworkEnforcementProjectionImportsStayMetadataOnly`

Sandboxworker package coverage:

- `TestWorkerSecurityPolicyAllowsExplicitNetworkEnforcementCapability`
- `TestServiceMicroVMCapabilityOutputDoesNotClaimDefaultNetworkEnforcement`
- `TestServiceCapabilitiesCanIncludeExplicitNetworkEnforcementCapability`

MicroVM package coverage:

- `TestDriverMetadataProjectsExplicitNetworkEnforcementAdapterSuccessAndFailure`
- `TestDriverNetworkEnforcementPlanningUsesInjectedBoundaryOnlyWhenConfigured`
- `TestDriverNetworkEnforcementPlanningWithoutAdapterFailsClosed`
- `TestMicroVMNetworkEnforcementPlanningImportsStayBoundaryOnly`
- `TestNewLiveDriverPassesExplicitNetworkEnforcementPlanningToMicroVMDriver`

Command boundary coverage:

- `TestSandboxdDefaultCapabilitiesDoNotClaimNetworkPolicyEnforcement`
- `TestSandboxdMicroVMDescriptorCanAdvertiseExplicitNetworkEnforcementCapability`
- `TestSandboxdRuntimeRegistrationRequestsNetworkPlanOnlyForExplicitMicroVMPath`
- `TestSandboxdProductionCodeDoesNotOwnNetworkEnforcementPlanningOrSetup`
- `TestSandboxHostFromWorkerMetadataMapsExplicitNetworkEnforcementCapability`
- `TestPhase42NetworkProxyEnforcementVerificationDocs`
- `TestPhase42NetworkProxyEnforcementFakeOnlyVerification`

## Non-Goals

Phase 42 does not implement real proxy listeners, listener socket lifecycle,
HTTP proxy routing, reverse proxy setup, firewall mutation, iptables/nftables
or pf rule application, credential injection, credential proxy delivery, tmpfs
secret delivery, SSH-agent forwarding, production microVM egress, guest network
device configuration, Firecracker SDK network configuration, cloud networking,
provider/runtime live integration, or live E2E network-policy enforcement.

Phase 42 does not make metadata-only network proxy sessions, worker posture, or
requested deny-by-default policy sufficient to claim enforcement. Adapter
failure and unsupported outcomes fail closed by clearing enforcing capability
upgrades.

## Future Handoff Areas

Future phases are responsible for real proxy listener lifecycle, concrete
firewall application, credential injection or broker delivery, production
microVM egress controls, Firecracker guest network configuration, host
privilege handling, operator documentation, and live E2E network-policy
verification.

Those phases should keep Phase 42's contract split intact: pure planning and
redaction stay in `internal/sandboxruntime/networkenforcement`, capability
truth remains in sandbox and worker metadata, microVM runtime integration stays
behind explicit injected planning options, and command code remains a wiring
boundary rather than an owner of proxy or firewall behavior.

## Review Notes

Keep this document and `cmd/phase42_network_proxy_enforcement_docs_test.go` in
sync when focused command selectors, test names, fake-safe boundaries, or
network enforcement capability semantics change. Guard changes should preserve
the fake-only default matrix and should not turn Phase 42 planning metadata
into a claim of live proxy, firewall, credential, or production microVM egress
support.
