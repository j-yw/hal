# Sandbox Runtime v2 Phase 45 Final Fake-Only Verification

Phase 45 final verification barrier is fake-only. It fans in the completed
network enforcement contract, lifecycle, aggregation, projection, microVM,
command, worker, and documentation guard work without adding default live test
requirements.

## Scope

The final barrier covers network enforcement contracts, listener lifecycle,
firewall/runtime rule lifecycle, aggregation, runtime projection, microVM
metadata, command and sandboxd security metadata, worker descriptors, and
optional live-test and documentation guards.

Default Phase 45 verification is fake-only and does not require network egress,
listener binding, root privileges, firewall mutation, KVM, Docker, Podman,
Firecracker, hypervisor runtime dependencies, live environment variables,
`hal sandboxd`, or optional live build tags.

Optional live coverage remains documented but excluded from the default matrix.
It stays behind the `network_enforcement_live` build tag and the explicit
`HAL_NETWORK_ENFORCEMENT_LIVE=1`, `HAL_NETWORK_ENFORCEMENT_LIVE_PROXY=1`, and
`HAL_NETWORK_ENFORCEMENT_LIVE_FIREWALL=1` opt-ins.

## Focused Fake-Only Selectors

Run network enforcement contract, listener lifecycle, firewall/runtime rule
lifecycle, and aggregation coverage:

```sh
go test -count=1 -timeout=180s ./internal/sandboxruntime/networkenforcement -run 'Test(LiveLifecycleJSONRepresentsProxyAndRuleState|NetworkEnforcementProductionImportsStayDataOnly|NetworkEnforcementImportBoundaryCoversPlanningAndAdapterFiles|NetworkEnforcementForbiddenImportListCoversLiveSurfaces|NetworkEnforcementImportBoundaryAllowsMetadataHelpersOnly|ProxyListenerLifecycleRunner|RuleLifecycleRunner|LiveEnforcement(Aggregation|Runner))'
```

Run runtime projection coverage:

```sh
go test -count=1 -timeout=180s ./internal/sandboxruntime -run 'Test(SandboxruntimeNetworkEnforcement|RuntimeNetworkEnforcement)'
```

Run microVM, Firecracker metadata, and explicit live-driver metadata handoff
coverage:

```sh
go test -count=1 -timeout=180s -run 'Test(Driver.*NetworkEnforcement|MicroVMNetworkEnforcement|BackendNetworkEnforcement|NewLiveDriverPassesExplicitNetworkEnforcementPlanningToMicroVMDriver)' ./internal/sandboxruntime/microvm ./internal/sandboxruntime/microvm/firecrackerhost ./internal/sandboxruntime/microvm/firecracker
```

Run command, sandboxd, sandbox-host mapping, and Phase 45 documentation guard
coverage:

```sh
go test -count=1 -timeout=180s ./cmd -run 'Test(CommandAndSandboxdProductionSecurityPathsAvoidLiveMutationDependencies|Sandboxd.*Network|SandboxHostFromWorkerMetadataMapsExplicitNetworkEnforcementCapability|Phase45(NetworkEnforcement|FinalFakeOnly))'
```

Run worker runtime descriptor and security-policy coverage:

```sh
go test -count=1 -timeout=180s ./internal/sandboxworker -run 'Test(ServiceMicroVMCapabilityOutputDoesNotClaimDefaultNetworkEnforcement|ServiceRuntimeDriverDescriptorProjectsNetworkSecurityFromActiveMetadataOnly|ServiceCapabilitiesCanIncludeExplicitNetworkEnforcementCapability|WorkerSecurityPolicy(DistinguishesRequestedFromEnforcedControls|RejectsOverstatedCapabilityClaims|AllowsExplicitNetworkEnforcementCapability))'
```

## Broad Default Verification

Run broad default fake-only tests for the Phase 45 touched packages:

```sh
go test -count=1 -timeout=300s ./internal/sandboxruntime/networkenforcement ./internal/sandboxruntime ./internal/sandboxruntime/microvm ./internal/sandboxruntime/microvm/firecrackerhost ./cmd ./internal/sandboxworker ./internal/sandboxruntime/microvm/firecracker
```

Run the repository default test suite:

```sh
go test -count=1 -timeout=420s ./...
```

Run repository typecheck by compiling tests without running test bodies:

```sh
go test -count=1 -timeout=300s -run '^$' ./...
```

Run vet, docs, build, and whitespace checks:

```sh
go vet ./...
make docs-check
make build
git diff --check
```

Run `golangci-lint run ./...` only when `golangci-lint` is installed. If it is
unavailable, report lint unavailable instead of reporting lint as passed.

## Optional Live Command

The optional live command is documented for prepared hosts only. It is not part
of default Phase 45 verification and must not be included in default test
commands:

```sh
go test -tags=network_enforcement_live -count=1 -timeout=120s ./internal/sandboxruntime/networkenforcement -run 'TestNetworkEnforcementLiveHarnessRequiresExplicitOptIn|TestNetworkEnforcementLivePrerequisiteSkipMessagesAreClearAndRedacted'
```

The current optional file is still a stub and skips after prerequisite checks.
Future live adapters must keep the explicit build tag, explicit environment
opt-ins, cleanup behavior, and sanitized warning surfaces before touching
listeners, firewall/runtime rules, or process state.

## PRD Generation And Scheduling

The generated PRD JSON for this phase is produced with the plain convert
command, not the granular convert mode. The exact command is
`hal convert <generated-prd-md> --validate --json`:

```sh
hal convert <generated-prd-md> --validate --json
```

The generated `.hal/prd.json` scheduling inventory is conservative:

| Story | dependsOn | conflictDomains | parallelSafe | barrier |
| --- | --- | --- | --- | --- |
| US-001 | [] | sandboxruntime/networkenforcement/contracts | false | false |
| US-002 | US-001 | sandboxruntime/networkenforcement/lifecycle | false | false |
| US-003 | US-001 | sandboxruntime/networkenforcement/lifecycle | false | false |
| US-004 | US-002, US-003 | sandboxruntime/networkenforcement/lifecycle | false | false |
| US-005 | US-004 | sandboxruntime/network-metadata | false | false |
| US-006 | US-005 | sandboxruntime/microvm/network-metadata | false | false |
| US-007 | US-005, US-006 | cmd/sandboxd-security-metadata | false | false |
| US-008 | US-005 | sandboxworker/security-descriptor | false | false |
| US-009 | US-001, US-004 | docs/network-enforcement | true | false |
| US-010 | US-001, US-002, US-003, US-004, US-005, US-006, US-007, US-008, US-009 | sandboxruntime/networkenforcement/contracts; sandboxruntime/networkenforcement/lifecycle; sandboxruntime/network-metadata; sandboxruntime/microvm/network-metadata; cmd/sandboxd-security-metadata; sandboxworker/security-descriptor; docs/network-enforcement | false | true |

US-010 is the only barrier story. All stories include conflictDomains and
parallelSafe metadata, and every non-initial story includes dependsOn metadata.

## Review Notes

Keep this document, `cmd/phase45_final_fake_only_verification_test.go`, and
`cmd/phase45_network_enforcement_live_guard_test.go` in sync when Phase 45
selectors, optional live guardrails, PRD scheduling metadata, or broad
verification commands change. The default verification matrix must remain
fake-only, and optional live commands must stay documented but manually
opt-in.
