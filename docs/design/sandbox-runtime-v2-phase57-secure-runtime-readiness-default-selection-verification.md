# Sandbox Runtime v2 Phase 57 Secure Runtime Readiness and Default Selection Verification

Phase 57 final docs/guard barrier for secure runtime readiness and default
selection. It fans in US-001 through US-007 and keeps the secure-default
selection contract explicit before later live E2E work.

The secure-default selection invariant: strict default selection is allowed
only when every configured sanitized proof source is ready, warning-free, and
proof-backed. Requested posture, planned metadata, compatibility labels,
advisory diagnostics, partial proof, or historical command/factory state is not
enough to select or report a strict secure default.

## Strict and Advisory Behavior

Strict mode blocks selection when any required proof is missing, unsupported,
failed, metadata-only, advisory-only, compatibility-only, partial, or
warning-bearing. A blocked strict decision must stop before runtime driver
construction, live worker calls, provider execution, credential reads, network
calls, firewall mutation, sandbox provisioning fallback, or any live runtime
action that could silently downgrade the secure-default request.

Compatibility and advisory modes render diagnostics only and must not claim
strict secure-default readiness. They may explain what strict mode would block,
but they remain best-effort compatibility surfaces. They do not promote
`best_effort`, `proxy`, env delivery, legacy auth sync, unresolved template
state, mutable template references, or warning-bearing evidence into strict
readiness.

## Proof Sources

Phase 56 provides active MicroVM isolation and active `proxy_firewall` network
proof. The Phase 56 proof-source boundary is owned by
`internal/sandboxruntime/networkenforcement`, `internal/sandboxruntime`, and
`internal/sandboxworker`: strict readiness accepts only sanitized active proxy
proof plus active firewall or runtime rule proof for a `deny_by_default`
posture, and rejects proxy-only, planned-only, failed, unsupported, partial,
metadata-only, or warning-bearing enforcement.

Phase 58 provides active brokered credential delivery proof. The Phase 58
proof-source boundary is owned by `internal/credentialdelivery`,
`internal/factory/credentialactivation`, `internal/sandboxruntime`, and
`internal/sandboxworker`: strict readiness accepts only sanitized active
brokered proof summaries for configured service-domain bindings through
`http_proxy`, `ssh_agent`, or `file_tmpfs`. Env delivery and legacy auth sync
remain compatibility diagnostics.

Phase 59 provides selected-template trust and digest-lock proof. The Phase 59
proof-source boundary is owned by `internal/sandboxtemplate`,
`internal/sandboxtemplate/acquisition`, `internal/sandboxruntime`, and
`internal/sandboxworker`: strict readiness accepts only sanitized selected
template evidence with trusted status and locked digest provenance for a
configured template requirement.

## Package Ownership

`internal/sandbox` owns the secure-default readiness policy and reason-code
projection. Its `internal/sandbox` import boundary keeps the classifier pure,
data-only, deterministic, and redaction-safe.

`internal/sandboxtarget` owns fail-closed secure-default/default-selection
behavior. Its `internal/sandboxtarget` import boundary keeps selection
command-agnostic and prevents Cobra, command packages, factory command
surfaces, provider internals, concrete runtime drivers, and live dependency
packages from becoming selection policy.

The `cmd` and `internal/factory` render-only boundary consumes sanitized
readiness decisions from `internal/sandbox` and `internal/sandboxtarget`.
`cmd` and `internal/factory` remain render-only consumers of sanitized
decisions. They may pass through policy modes, clone decisions, persist safe
summaries, render JSON/human output, and record policy-decision metadata. They
must not own secure-default classification, construct proof evidence directly,
evaluate Phase 56 network enforcement, evaluate Phase 59 template trust policy,
or run Phase 58 credential activation implementation.

## Reason Codes and Redaction

Stable reason-code expectations include `readiness_missing`, `readiness_ready`,
`microvm_readiness_missing`, `network_enforcement_partial`,
`network_enforcement_confirmed`, `credential_activation_missing`,
`credential_activation_confirmed`, `template_lock_digest_missing`,
`selected_template_trust_confirmed`, and `warning_bearing`. New reason codes
must be additive, deterministic, and safe enum-like labels.

Readiness output, command JSON, human summaries, manifests, factory run
records, factory status/list output, and policy events must not expose raw
credentials, raw paths, endpoint URLs, hostnames, socket paths, firewall
commands or rules, network destinations, provider internals, raw template
references, registry tokens, local temporary paths, or live provider details.
Outputs should carry only safe proof IDs, binding IDs, modes, statuses, source
labels, aggregate counts, and reason codes.

## Default Fake-Only Verification

Default Phase 57 verification is fake-only. Default verification must not
require root, KVM, firewall mutation, live network egress, cloud/provider
credentials, Docker/Podman daemons, Docker sockets, real credentials, live
registries, live worker daemons, `hal sandboxd`, or `hal run`.

Run secure-default readiness policy, projection, reason-code, and redaction
coverage:

```sh
go test -count=1 -timeout=180s ./internal/sandbox -run 'Test(US001SecureDefault|SecureDefaultReadiness|US002ProjectSecureDefault|ProjectSecureDefaultReadinessInput|US004SelectedTemplate|US006SelectedTemplate|SecurityCapabilityReadinessGate)'
```

Run Phase 56 network/isolation proof-source projection and Phase 58 runtime
and worker credential-proof projection coverage:

```sh
go test -count=1 -timeout=180s ./internal/sandboxruntime/networkenforcement ./internal/sandboxruntime ./internal/sandboxworker -run 'Test(LiveEnforcementAggregationRequiresBothActiveSides|RuntimeNetworkEnforcementProxyOnlyProofCannotClaimProxyFirewall|ServiceStatusProjectsStrictNetworkSecurityOnlyFromActiveDualProof|RuntimeCredentialDeliveryProjectsActiveSecureProofSummaries|WorkerSecurityProjectsRuntimeCredentialDeliveryProofSummaries)'
```

Run Phase 58 credential delivery planning, activation, proof-summary, and
fake-only import-boundary coverage:

```sh
go test -count=1 -timeout=180s ./internal/credentialdelivery ./internal/factory/credentialactivation -run 'Test(US003|CredentialActivation|CredentialDelivery|ActivateDelivery|HTTPProxyHandoffActivation|SSHAgentHandoffActivation|FileTmpfsSimulation)'
```

Run Phase 59 template source, trust policy, provenance, and fake acquisition
coverage:

```sh
go test -count=1 -timeout=180s ./internal/sandboxtemplate ./internal/sandboxtemplate/acquisition -run 'Test(US004TemplateReferenceClassificationSeparatesDigestLockedAndMutableInput|EvaluateTrustPolicyStrictRejectsEveryRolloutPolicyCode|ProjectRuntimeTemplateLockMetadataSurfacesSanitizedTrustPolicyOutcome|SandboxTemplateProductionImportsStayPure|SandboxTemplateAcquisitionProductionImportsStayFakeSafe|TrustPolicyProductionImportsStayDataOnly)'
```

Run fail-closed default target selection and `internal/sandboxtarget` import
boundary coverage:

```sh
go test -count=1 -timeout=180s ./internal/sandboxtarget -run 'Test(SelectStrictSecureDefault|SelectCompatibilitySecureDefault|SandboxtargetImportsStayCommandAgnostic|SandboxtargetForbiddenImportListCoversCommandCouplingSurfaces)'
```

Run command/factory/status render-only, redaction, strict blocked, proof
complete, compatibility/advisory, and Phase 57 docs/guard coverage:

```sh
go test -count=1 -timeout=180s ./cmd -run 'Test(US005(CommandNetworkSecurityDowngradesProxyFirewallWithoutRuntimeProof|SandboxRuntimeStatusJSONRequiresActiveDualNetworkProof|FactoryStrictReadinessBlocksDowngradedProxyFirewallMetadata|CommandStatusReadinessFilesAvoidLiveEnforcementImplementation)|US006(RunSandboxStrictSelectionJSONRendersAndPersistsDecision|AutoSandboxStrictSelectionJSONRendersAndPersistsDecision|RunSandboxJSONAugmentsAllowedAndCompatibilityGateDecisions|RunSandboxStrictHumanErrorIncludesGateCountsAndReasons)|US007(FactoryRunResultSurfacesSecurityReadinessGateOutcomes|FactoryStatusSurfacesSecurityReadinessGateSummary)|Phase57)'
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

## Phase 60 Live E2E Separation

Phase 60 live E2E remains outside Phase 57 default verification. Phase 57 does
not add a live E2E command and does not make live prerequisites part of the
default matrix. Any later live E2E verification must stay explicit,
environment-gated, build-tagged, sanitized on skip/failure, and separate from
the fake-only Phase 57 release gate.

## Barrier Story

| Story | dependsOn | conflictDomains | parallelSafe | barrier |
| --- | --- | --- | --- | --- |
| US-001 | [] | internal/sandbox | false | false |
| US-002 | US-001 | internal/sandbox; internal/sandboxruntime; internal/sandboxruntime/networkenforcement; internal/sandboxruntime/microvm | false | false |
| US-003 | US-001 | internal/sandbox; internal/credentialdelivery; internal/factory/credentialactivation | false | false |
| US-004 | US-001 | internal/sandbox; internal/sandboxtemplate; internal/sandboxtemplate/acquisition; internal/sandboxruntime; internal/sandboxworker | false | false |
| US-005 | US-002, US-003, US-004 | internal/sandboxtarget; internal/sandbox | false | false |
| US-006 | US-005 | cmd; internal/sandboxexec; internal/sandboxexecution | false | false |
| US-007 | US-005 | cmd; internal/factory; internal/sandboxexec; internal/sandboxexecution | false | false |
| US-008 | US-001, US-002, US-003, US-004, US-005, US-006, US-007 | docs/design; docs/cli; docs/contracts; cmd; docs/guards | false | true |

US-008 is the single final docs/guard barrier story for Phase 57. Keep this
document and `cmd/phase57_secure_default_selection_docs_test.go` in sync when
secure-default readiness policy, default target selection, proof-source
projection, command/factory rendering, redaction, or fake-only verification
boundaries change.
