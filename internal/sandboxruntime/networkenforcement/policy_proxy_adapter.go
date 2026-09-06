package networkenforcement

import "context"

const policyProxyEnforcementAdapterID = "policy-proxy-enforcement"

// PolicyProxyEnforcementAdapter adapts policy proxy lifecycle proof into the
// network enforcement Adapter contract. It can prove proxy enforcement only;
// firewall/runtime deny-by-default capability still requires rule lifecycle
// proof through LiveEnforcementRunner.
type PolicyProxyEnforcementAdapter struct {
	Service PolicyProxyService
}

var _ Adapter = PolicyProxyEnforcementAdapter{}

// NewPolicyProxyEnforcementAdapter wires a proxy listener adapter through the
// concrete policy proxy lifecycle service and exposes it as an Adapter.
func NewPolicyProxyEnforcementAdapter(listener ProxyListenerAdapter) PolicyProxyEnforcementAdapter {
	return PolicyProxyEnforcementAdapter{
		Service: PolicyProxyLifecycleService{Adapter: listener},
	}
}

// EnforceNetwork starts the proxy, verifies active lifecycle proof, and returns
// a proxy-only adapter result. Active-check failures fail closed and attempt
// cleanup before reporting sanitized warnings.
func (a PolicyProxyEnforcementAdapter) EnforceNetwork(ctx context.Context, plan SanitizedPlan) Result {
	input := plan.Plan()
	if a.Service == nil {
		return ResultFromPolicyProxyLifecycleProof(input, failedPolicyProxyLifecycleProof(input, ProxyListenerLifecycleMetadata{}, PolicyProxyLifecycleOperationStart, LifecycleReasonAdapterUnsupported, nil))
	}

	request := SanitizePolicyProxyLifecycleRequest(PolicyProxyLifecycleRequest{Plan: plan})
	started, err := a.Service.StartPolicyProxy(ctx, request)
	if err != nil {
		return ResultFromPolicyProxyLifecycleProof(input, started)
	}

	activeRequest := SanitizePolicyProxyLifecycleRequest(PolicyProxyLifecycleRequest{
		Plan:      plan,
		Requested: started,
		Active:    started,
	})
	active, err := a.Service.ActivePolicyProxy(ctx, activeRequest)
	if err != nil {
		active.WarningCodes = appendLifecycleWarnings(active.WarningCodes, LifecycleWarningActiveCheckFailed)
		stopped, stopErr := a.Service.StopPolicyProxy(ctx, SanitizePolicyProxyLifecycleRequest(PolicyProxyLifecycleRequest{
			Plan:      plan,
			Requested: started,
			Active:    started,
		}))
		active = policyProxyLifecycleProofWithWarnings(active, stopped.WarningCodes...)
		if stopErr != nil {
			active = policyProxyLifecycleProofWithWarnings(active, LifecycleWarningCleanupFailed, LifecycleWarningSanitizedAdapterError)
		}
		return ResultFromPolicyProxyLifecycleProof(input, active)
	}

	return ResultFromPolicyProxyLifecycleProof(input, active)
}

// ResultFromPolicyProxyLifecycleProof projects active policy proxy lifecycle
// proof into an Adapter result without upgrading to proxy_firewall or
// deny-by-default capability.
func ResultFromPolicyProxyLifecycleProof(plan Plan, proof PolicyProxyLifecycleProof) Result {
	input := SanitizePlan(plan)
	proof = SanitizePolicyProxyLifecycleProof(proof)
	warnings := resultWarningsFromPolicyProxyProof(proof)
	operations := policyProxyLifecycleOperationsAsStrings(proof)
	policySnapshot := proof.PolicySnapshot
	if policySnapshot == nil {
		policySnapshot = sanitizePolicySnapshotIdentityPtr(input.PolicySnapshot)
	}
	adapterID := proof.AdapterID
	if adapterID == "" {
		adapterID = policyProxyEnforcementAdapterID
	}

	if policyProxyLifecycleProofActive(proof) {
		return SanitizeResult(Result{
			PlanID:          resultPlanIDFromPolicyProxyProof(input, proof),
			AdapterID:       adapterID,
			Outcome:         ResultOutcomeSuccess,
			EnforcementMode: ResultModeProxy,
			Mechanisms:      []EnforcementMechanism{EnforcementMechanismProxy},
			Operations:      operations,
			PolicySnapshot:  policySnapshot,
			Capability:      proxyOnlyResultCapability(input),
			ReasonCode:      ResultReasonApplied,
			WarningCodes:    warnings,
		})
	}

	return SanitizeResult(Result{
		PlanID:          resultPlanIDFromPolicyProxyProof(input, proof),
		AdapterID:       adapterID,
		Outcome:         policyProxyProofFailureOutcome(proof),
		EnforcementMode: ResultModeNone,
		Operations:      operations,
		PolicySnapshot:  policySnapshot,
		ReasonCode:      policyProxyProofFailureReason(proof),
		WarningCodes:    warnings,
	})
}

func resultPlanIDFromPolicyProxyProof(plan Plan, proof PolicyProxyLifecycleProof) string {
	if proof.PlanID != "" {
		return proof.PlanID
	}
	return plan.ID
}

func policyProxyLifecycleProofWithWarnings(proof PolicyProxyLifecycleProof, warnings ...LifecycleWarningCode) PolicyProxyLifecycleProof {
	proof.WarningCodes = appendLifecycleWarnings(proof.WarningCodes, warnings...)
	return finalizePolicyProxyLifecycleProof(proof)
}

func proxyOnlyResultCapability(plan Plan) *ResultCapability {
	capability := &ResultCapability{
		Supported: true,
		Modes:     []ResultMode{ResultModeProxy},
	}
	if plan.Allowlist != nil {
		for _, category := range plan.Allowlist.RuleCategories {
			switch category {
			case AllowlistRuleCategoryDomain:
				capability.SupportsDomainRules = true
			case AllowlistRuleCategoryEndpoint:
				capability.SupportsEndpointRules = true
			case AllowlistRuleCategoryPrivateRange:
				capability.SupportsPrivateRangeRules = true
			case AllowlistRuleCategoryMetadataEndpoint:
				capability.SupportsMetadataEndpoint = true
			case AllowlistRuleCategoryLoopback:
				capability.SupportsLoopbackRules = true
			case AllowlistRuleCategoryLinkLocal:
				capability.SupportsLinkLocalRules = true
			}
		}
	}
	if plan.Category != nil {
		if plan.Category.PrivateNetwork == PostureBlock {
			capability.SupportsPrivateRangeRules = true
		}
		if plan.Category.MetadataEndpoint == PostureBlock {
			capability.SupportsMetadataEndpoint = true
		}
	}
	return sanitizeResultCapabilityPtr(capability)
}

func policyProxyProofFailureOutcome(proof PolicyProxyLifecycleProof) ResultOutcome {
	if proof.ReasonCode == LifecycleReasonAdapterUnsupported {
		return ResultOutcomeUnsupported
	}
	return ResultOutcomeFailure
}

func policyProxyProofFailureReason(proof PolicyProxyLifecycleProof) ResultReasonCode {
	switch proof.ReasonCode {
	case LifecycleReasonAdapterUnsupported:
		return ResultReasonAdapterUnsupported
	case LifecycleReasonCapabilityMissing:
		return ResultReasonCapabilityMissing
	default:
		if len(proof.WarningCodes) == 0 && proof.Status != LifecycleStatusFailed {
			return ResultReasonCapabilityMissing
		}
		return ResultReasonAdapterFailed
	}
}

func resultWarningsFromPolicyProxyProof(proof PolicyProxyLifecycleProof) []ResultWarningCode {
	var warnings []ResultWarningCode
	if lifecycleWarningCodeContains(proof.WarningCodes, LifecycleWarningSanitizedAdapterError) {
		warnings = appendResultWarnings(warnings, ResultWarningSanitizedAdapterError)
	}
	if lifecycleWarningCodeContains(proof.WarningCodes, LifecycleWarningActiveCheckFailed) ||
		lifecycleWarningCodeContains(proof.WarningCodes, LifecycleWarningCleanupFailed) ||
		lifecycleWarningCodeContains(proof.WarningCodes, LifecycleWarningPartialLifecycle) {
		warnings = appendResultWarnings(warnings, ResultWarningPartialEnforcement)
	}
	return warnings
}
