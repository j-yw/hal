# Sandbox Runtime v2 Phase 56 Live Gate Default Fake-Only Verification

Phase 56 final live-gate documentation and default fake-only guard is the only
explicit final docs/guard barrier story for Phase 56. It fans in the completed
US-001 through US-005 work and keeps future live firewall/runtime enforcement
opt-in only.

The secure-default invariant: `proxy_firewall` with `deny_by_default` is
reported only after sanitized active proxy proof and active firewall or runtime
rule proof. A requested strict policy, a configured plan, a successful proxy
only proof, or compatibility metadata alone must not satisfy strict readiness.

## Operator Meaning

`proxy` means active proxy proof without active firewall or runtime rule proof.
It can show that the proxy side of the proof is alive, but strict
secure-default readiness remains blocked.

`proxy_firewall` means active proxy proof plus active firewall or runtime rule
proof. It is the strong dual-proof network enforcement mode and is valid only
when sanitized lifecycle metadata is active, successful, warning-free, and
capable of the default-deny posture.

`best_effort` means partial, advisory, unsupported, warning-bearing, or
compatibility enforcement that must not satisfy strict readiness. Operators
should treat it as useful posture context, not as proven default-deny
enforcement.

`deny_by_default` means the requested/effective default-deny network posture,
not proof by itself. It becomes a strict secure-default claim only when paired
with `proxy_firewall` proof and sanitized default-deny capability labels.

## Default Fake-Only Verification

Default Phase 56 verification is fake-only. It must not require root, KVM,
pfctl, iptables, nftables, Docker, Podman, cloud credentials, real network
egress, or live worker daemons. It must also avoid optional live build tags,
live environment values, live proxy listener binding, firewall mutation,
runtime rule mutation, Firecracker launch, provider probing, and external
network access.

Run network enforcement aggregation, rule proof, live-gate seam, and
import-boundary coverage:

```sh
go test -count=1 -timeout=180s ./internal/sandboxruntime/networkenforcement -run 'Test(LiveEnforcementAggregationRequires(DefaultDenyRuleCapabilityProof|BothActiveSides)|LiveEnforcementAggregationDowngradesPartialAndMetadataOnlyResults|LiveEnforcementRunner(FailsClosedForNilAndPartialAdapters|OrchestratesBothSidesBeforeClaimingStrongMode)|RuleProofAdapters(RepresentFirewallAndRuntimeLifecycle|NilDisabledDefaultBuildAndBestEffortNeverStrictReady)|RuleProofLiveGateSeamsRequireBuildTagAndEnvironmentMarkers|NetworkEnforcementProductionImportsStayDataOnly|NetworkEnforcementForbiddenImportListCoversLiveSurfaces|Phase56NetworkEnforcementImportBoundaryRejectsCommandFactoryAndCobra)'
```

Run runtime projection, microVM wiring, firecrackerhost wiring, and worker
security projection coverage:

```sh
go test -count=1 -timeout=180s ./internal/sandboxruntime ./internal/sandboxruntime/microvm ./internal/sandboxruntime/microvm/firecrackerhost ./internal/sandboxworker -run 'Test(RuntimeNetworkEnforcement(ProxyOnlyProofCannotClaimProxyFirewall|FailureClearsCapabilityUpgrade)|GatedNetworkEnforcementPlanning(RoutesThroughRuntimeContracts|MissingGateDoesNotInvokeLiveAdapters|DisabledRuleAdapterDoesNotSatisfyStrictReadiness)|LiveNetworkEnforcementPlanningDefaultBuildIgnoresEnvGatesAndDoesNotInvokeAdapters|NewLiveDriver(CanUseMicroVMGatedNetworkEnforcementWiring|NetworkEnforcement(MissingGateDoesNotStartProxyOrRules|LiveOptionUsesBuildTagGate))|ServiceStatusProjects(ProxyActiveNetworkEnforcementProof|StrictNetworkSecurityOnlyFromActiveDualProof)|ServiceStatusDoesNotUpgradeNetworkEnforcementWithoutActiveSuccessfulProxyProof)'
```

Run command status/readiness projection, default fake-only, and command-boundary
guards:

```sh
go test -count=1 -timeout=180s ./cmd -run 'Test(Phase50DefaultGoTestSuiteDoesNotRequireLivePrerequisites|US005(CommandNetworkSecurityDowngradesProxyFirewallWithoutRuntimeProof|SandboxRuntimeStatusJSONRequiresActiveDualNetworkProof|FactoryStrictReadinessBlocksDowngradedProxyFirewallMetadata|CommandStatusReadinessFilesAvoidLiveEnforcementImplementation)|Phase55CommandProductionCodeDoesNotOwnPolicyProxyImplementation|Phase56(LiveGateDocumentation|DefaultCommandsStayFakeOnly|DocumentedFocusedSelectorsMatchTestsAndPackages|CommandProductionCodeDoesNotOwnFirewallProxyOrRuntimeImplementation|SingleFinalDocsGuardStory))'
```

Run the broad fake-only quality gate:

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

## Optional Live Verification

Optional live checks are outside the default matrix. They are operator-run
diagnostics for prepared hosts only, and they must skip with sanitized
missing-prerequisite diagnostics before listener binding, firewall mutation,
runtime rule mutation, Firecracker launch, worker daemon use, cloud probing, or
network egress.

The relevant optional build tags are `network_enforcement_live`,
`microvm_e2e_live`, and `firecracker_live`. Phase 56 live firewall/runtime
proofs require explicit environment gate names only, never secret values:
`HAL_NETWORK_ENFORCEMENT_LIVE`, `HAL_NETWORK_ENFORCEMENT_LIVE_PROXY`,
`HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL`, and
`HAL_NETWORK_ENFORCEMENT_LIVE_RUNTIME`.

Run standalone network enforcement live gate checks only on an intentionally
prepared host:

```sh
env HAL_NETWORK_ENFORCEMENT_LIVE=<set> HAL_NETWORK_ENFORCEMENT_LIVE_PROXY=<set> HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL=<set> HAL_NETWORK_ENFORCEMENT_LIVE_RUNTIME=<set> go test -tags=network_enforcement_live -count=1 -timeout=120s ./internal/sandboxruntime/networkenforcement -run 'TestNetworkEnforcementLiveHarnessRequiresExplicitOptIn|TestNetworkEnforcementLivePrerequisiteSkipMessagesAreClearAndRedacted'
```

The optional live command is not a release requirement and must not be moved
into the default fake-only section. Future live checks may add narrower
adapter-specific gates, but must keep the global network gate, mechanism gate,
safe skip diagnostics, and sanitized cleanup warnings.

## Barrier Story

| Story | dependsOn | conflictDomains | parallelSafe | barrier |
| --- | --- | --- | --- | --- |
| US-001 | [] | internal/sandboxruntime/networkenforcement | false | false |
| US-002 | US-001 | internal/sandboxruntime/networkenforcement | false | false |
| US-003 | US-002 | internal/sandboxruntime/microvm; internal/sandboxruntime/microvm/firecrackerhost | false | false |
| US-004 | US-002, US-003 | internal/sandboxworker | false | false |
| US-005 | US-004 | cmd | false | false |
| US-006 | US-002, US-003, US-004, US-005 | docs/guards; cmd; internal/sandboxruntime/networkenforcement; internal/sandboxruntime/microvm; internal/sandboxworker | false | true |

US-006 is the only explicit final docs/guard barrier story for Phase 56. Keep
this document, `cmd/phase56_live_gate_docs_test.go`, and the focused selectors
above in sync when live firewall/runtime enforcement gates or projection
guards change.
