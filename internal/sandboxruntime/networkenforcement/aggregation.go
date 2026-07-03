package networkenforcement

import "context"

const liveEnforcementAggregationAdapterID = "live-enforcement-aggregation"

// LiveEnforcementRunner coordinates the fakeable live listener and rule
// lifecycle runners, then emits a single adapter-style result. It claims a
// strong enforcement mode only when both sides report active success.
type LiveEnforcementRunner struct {
	Listener ProxyListenerLifecycleRunner
	Rules    RuleLifecycleRunner
}

// EnforceNetwork implements Adapter using the live lifecycle runners. The
// orchestration remains fake-only: concrete listener, firewall, or runtime
// mutation can only happen behind injected lifecycle adapters.
func (r LiveEnforcementRunner) EnforceNetwork(ctx context.Context, plan SanitizedPlan) Result {
	input := plan.Plan()
	listener, listenerErr := r.Listener.Start(ctx, input)
	if listenerErr != nil {
		return AggregateLiveEnforcementResult(input, &listener, nil)
	}

	rules, ruleErr := r.Rules.Apply(ctx, input)
	if ruleErr != nil {
		stopped, _ := r.Listener.Stop(ctx, input, listener.Active)
		listener = aggregateListenerCleanupWarnings(listener, stopped)
		return AggregateLiveEnforcementResult(input, &listener, &rules)
	}

	return AggregateLiveEnforcementResult(input, &listener, &rules)
}

// AggregateLiveEnforcementResult combines sanitized listener and
// firewall/runtime rule lifecycle metadata into the adapter Result contract.
// Requested or planned metadata alone never upgrades to strong enforcement.
func AggregateLiveEnforcementResult(plan Plan, listener *ProxyListenerLifecycleResult, rules *RuleLifecycleResult) Result {
	input := SanitizePlan(plan)
	listenerResult := sanitizeAggregateListenerResult(listener)
	ruleResult := sanitizeAggregateRuleResult(rules)

	warnings := aggregateResultWarnings(listenerResult, ruleResult)
	mechanisms := aggregateResultMechanisms(input, listenerResult, ruleResult)
	operations := aggregateResultOperations(listenerResult, ruleResult)
	policySnapshot := sanitizePolicySnapshotIdentityPtr(input.PolicySnapshot)

	if aggregatePlanAllowsStrongEnforcement(input) &&
		aggregateListenerActive(listenerResult) &&
		aggregateRulesActive(ruleResult) {
		mode := aggregateStrongResultMode(ruleResult)
		if resultModeCanEnforce(mode) {
			return SanitizeResult(Result{
				PlanID:          input.ID,
				AdapterID:       liveEnforcementAggregationAdapterID,
				Outcome:         ResultOutcomeSuccess,
				EnforcementMode: mode,
				Mechanisms:      mechanisms,
				Operations:      operations,
				PolicySnapshot:  policySnapshot,
				Capability:      aggregateResultCapability(input, mode),
				ReasonCode:      ResultReasonApplied,
				WarningCodes:    warnings,
			})
		}
	}

	if aggregateBestEffortPlan(input) &&
		aggregateListenerActive(listenerResult) &&
		aggregateRulesActive(ruleResult) {
		return SanitizeResult(Result{
			PlanID:          input.ID,
			AdapterID:       liveEnforcementAggregationAdapterID,
			Outcome:         ResultOutcomeBestEffort,
			EnforcementMode: ResultModeBestEffort,
			Mechanisms:      mechanisms,
			Operations:      operations,
			PolicySnapshot:  policySnapshot,
			ReasonCode:      ResultReasonBestEffort,
			WarningCodes:    appendResultWarnings(warnings, ResultWarningCapabilityDowngraded),
		})
	}

	outcome := ResultOutcomeFailure
	reason := ResultReasonAdapterFailed
	if aggregateUnsupported(listenerResult, ruleResult) {
		outcome = ResultOutcomeUnsupported
		reason = ResultReasonAdapterUnsupported
	}
	if !aggregateLifecycleFailed(listenerResult, ruleResult) && outcome == ResultOutcomeFailure {
		reason = ResultReasonCapabilityMissing
	}

	return SanitizeResult(Result{
		PlanID:          input.ID,
		AdapterID:       liveEnforcementAggregationAdapterID,
		Outcome:         outcome,
		EnforcementMode: ResultModeNone,
		Mechanisms:      mechanisms,
		Operations:      operations,
		PolicySnapshot:  policySnapshot,
		ReasonCode:      reason,
		WarningCodes:    warnings,
	})
}

func aggregateListenerCleanupWarnings(started, stopped ProxyListenerLifecycleResult) ProxyListenerLifecycleResult {
	stopped = SanitizeProxyListenerLifecycleResult(stopped)
	if len(stopped.WarningCodes) == 0 {
		return started
	}
	started.WarningCodes = appendLifecycleWarnings(started.WarningCodes, stopped.WarningCodes...)
	if started.Active != nil {
		started.Active.WarningCodes = appendLifecycleWarnings(started.Active.WarningCodes, stopped.WarningCodes...)
	}
	return SanitizeProxyListenerLifecycleResult(started)
}

func sanitizeAggregateListenerResult(result *ProxyListenerLifecycleResult) *ProxyListenerLifecycleResult {
	if result == nil {
		return nil
	}
	sanitized := SanitizeProxyListenerLifecycleResult(*result)
	return &sanitized
}

func sanitizeAggregateRuleResult(result *RuleLifecycleResult) *RuleLifecycleResult {
	if result == nil {
		return nil
	}
	sanitized := SanitizeRuleLifecycleResult(*result)
	return &sanitized
}

func aggregatePlanAllowsStrongEnforcement(plan Plan) bool {
	return plan.Proxy != nil &&
		plan.Firewall != nil &&
		plan.Firewall.Mode == FirewallIntentModeApply
}

func aggregateBestEffortPlan(plan Plan) bool {
	if plan.Firewall == nil {
		return false
	}
	switch plan.Firewall.Mode {
	case FirewallIntentModePrepare, FirewallIntentModeAuditOnly:
		return true
	default:
		return false
	}
}

func aggregateListenerActive(result *ProxyListenerLifecycleResult) bool {
	if result == nil || result.Active == nil {
		return false
	}
	return result.Status == LifecycleStatusActive &&
		result.ReasonCode == LifecycleReasonActive &&
		len(result.WarningCodes) == 0 &&
		result.Active.Status == LifecycleStatusActive &&
		result.Active.ReasonCode == LifecycleReasonActive &&
		len(result.Active.WarningCodes) == 0
}

func aggregateRulesActive(result *RuleLifecycleResult) bool {
	if result == nil || result.Active == nil {
		return false
	}
	return result.Status == LifecycleStatusActive &&
		result.ReasonCode == LifecycleReasonActive &&
		len(result.WarningCodes) == 0 &&
		result.Active.Status == LifecycleStatusActive &&
		result.Active.ReasonCode == LifecycleReasonActive &&
		len(result.Active.WarningCodes) == 0
}

func aggregateStrongResultMode(rules *RuleLifecycleResult) ResultMode {
	if rules == nil || rules.Active == nil {
		return ResultModeNone
	}
	for _, mechanism := range rules.Active.Mechanisms {
		switch mechanism {
		case EnforcementMechanismFirewall:
			return ResultModeProxyFirewall
		case EnforcementMechanismRuntime:
			return ResultModeRuntime
		}
	}
	return ResultModeNone
}

func aggregateResultMechanisms(plan Plan, listener *ProxyListenerLifecycleResult, rules *RuleLifecycleResult) []EnforcementMechanism {
	var mechanisms []EnforcementMechanism
	if listener != nil && listener.Active != nil {
		mechanisms = appendEnforcementMechanisms(mechanisms, listener.Active.Mechanisms...)
	}
	if rules != nil && rules.Active != nil {
		mechanisms = appendEnforcementMechanisms(mechanisms, rules.Active.Mechanisms...)
	}
	if len(mechanisms) == 0 {
		if plan.Proxy != nil {
			mechanisms = appendEnforcementMechanisms(mechanisms, plan.Proxy.Mechanism)
		}
		if plan.Firewall != nil {
			mechanisms = appendEnforcementMechanisms(mechanisms, plan.Firewall.Mechanism)
		}
	}
	return mechanisms
}

func appendEnforcementMechanisms(existing []EnforcementMechanism, values ...EnforcementMechanism) []EnforcementMechanism {
	for _, value := range values {
		current := sanitizeEnforcementMechanism(value)
		if current == "" || current == EnforcementMechanismNone || enforcementMechanismContains(existing, current) {
			continue
		}
		existing = append(existing, current)
	}
	if len(existing) == 0 {
		return nil
	}
	return existing
}

func enforcementMechanismContains(values []EnforcementMechanism, target EnforcementMechanism) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func aggregateResultOperations(listener *ProxyListenerLifecycleResult, rules *RuleLifecycleResult) []string {
	var operations []string
	if listener != nil && listener.Active != nil {
		operations = appendSanitizedIdentifiers(operations, listener.Active.Operations...)
	}
	if rules != nil && rules.Active != nil {
		operations = appendSanitizedIdentifiers(operations, rules.Active.Operations...)
	}
	return sanitizeIdentifierList(operations)
}

func aggregateResultCapability(plan Plan, mode ResultMode) *ResultCapability {
	if !resultModeCanEnforce(mode) {
		return nil
	}
	capability := &ResultCapability{
		Supported:                  true,
		Modes:                      []ResultMode{mode},
		SupportsDefaultDenyPosture: plan.DefaultPosture == DefaultPostureDenyByDefault,
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

func aggregateResultWarnings(listener *ProxyListenerLifecycleResult, rules *RuleLifecycleResult) []ResultWarningCode {
	var warnings []ResultWarningCode
	if aggregatePartialLifecycle(listener, rules) {
		warnings = appendResultWarnings(warnings, ResultWarningPartialEnforcement)
	}
	if aggregateLifecycleHasWarning(listenerLifecycleWarnings(listener), LifecycleWarningSanitizedAdapterError) ||
		aggregateLifecycleHasWarning(ruleLifecycleWarnings(rules), LifecycleWarningSanitizedAdapterError) {
		warnings = appendResultWarnings(warnings, ResultWarningSanitizedAdapterError)
	}
	if aggregateLifecycleHasWarning(listenerLifecycleWarnings(listener), LifecycleWarningCleanupFailed) ||
		aggregateLifecycleHasWarning(ruleLifecycleWarnings(rules), LifecycleWarningCleanupFailed) ||
		aggregateLifecycleHasWarning(ruleLifecycleWarnings(rules), LifecycleWarningRollbackFailed) ||
		aggregateLifecycleHasWarning(ruleLifecycleWarnings(rules), LifecycleWarningActiveCheckFailed) {
		warnings = appendResultWarnings(warnings, ResultWarningPartialEnforcement)
	}
	if listener == nil && rules == nil {
		warnings = appendResultWarnings(warnings, ResultWarningMetadataOnlyFallback)
	}
	return warnings
}

func appendResultWarnings(existing []ResultWarningCode, values ...ResultWarningCode) []ResultWarningCode {
	out := sanitizeResultWarningCodeList(existing)
	for _, value := range values {
		current := sanitizeResultWarningCode(value)
		if current == "" || resultWarningCodeContains(out, current) {
			continue
		}
		out = append(out, current)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func resultWarningCodeContains(values []ResultWarningCode, target ResultWarningCode) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func aggregatePartialLifecycle(listener *ProxyListenerLifecycleResult, rules *RuleLifecycleResult) bool {
	listenerActive := aggregateListenerActiveIgnoringWarnings(listener)
	rulesActive := aggregateRulesActiveIgnoringWarnings(rules)
	return listenerActive != rulesActive
}

func aggregateListenerActiveIgnoringWarnings(result *ProxyListenerLifecycleResult) bool {
	if result == nil || result.Active == nil {
		return false
	}
	return result.Status == LifecycleStatusActive &&
		result.Active.Status == LifecycleStatusActive &&
		result.Active.ReasonCode == LifecycleReasonActive
}

func aggregateRulesActiveIgnoringWarnings(result *RuleLifecycleResult) bool {
	if result == nil || result.Active == nil {
		return false
	}
	return result.Status == LifecycleStatusActive &&
		result.Active.Status == LifecycleStatusActive &&
		result.Active.ReasonCode == LifecycleReasonActive
}

func listenerLifecycleWarnings(result *ProxyListenerLifecycleResult) []LifecycleWarningCode {
	if result == nil {
		return nil
	}
	warnings := appendLifecycleWarnings(nil, result.WarningCodes...)
	if result.Active != nil {
		warnings = appendLifecycleWarnings(warnings, result.Active.WarningCodes...)
	}
	return warnings
}

func ruleLifecycleWarnings(result *RuleLifecycleResult) []LifecycleWarningCode {
	if result == nil {
		return nil
	}
	warnings := appendLifecycleWarnings(nil, result.WarningCodes...)
	if result.Active != nil {
		warnings = appendLifecycleWarnings(warnings, result.Active.WarningCodes...)
	}
	return warnings
}

func aggregateLifecycleHasWarning(warnings []LifecycleWarningCode, target LifecycleWarningCode) bool {
	for _, warning := range warnings {
		if warning == target {
			return true
		}
	}
	return false
}

func aggregateUnsupported(listener *ProxyListenerLifecycleResult, rules *RuleLifecycleResult) bool {
	if listener == nil && rules == nil {
		return true
	}
	return aggregateListenerReason(listener) == LifecycleReasonAdapterUnsupported ||
		aggregateRuleReason(rules) == LifecycleReasonAdapterUnsupported
}

func aggregateLifecycleFailed(listener *ProxyListenerLifecycleResult, rules *RuleLifecycleResult) bool {
	if listener != nil && listener.Status == LifecycleStatusFailed {
		return true
	}
	if listener != nil && listener.Active != nil && listener.Active.Status == LifecycleStatusFailed {
		return true
	}
	if rules != nil && rules.Status == LifecycleStatusFailed {
		return true
	}
	if rules != nil && rules.Active != nil && rules.Active.Status == LifecycleStatusFailed {
		return true
	}
	return false
}

func aggregateListenerReason(result *ProxyListenerLifecycleResult) LifecycleReasonCode {
	if result == nil {
		return ""
	}
	if result.ReasonCode != "" {
		return result.ReasonCode
	}
	if result.Active != nil {
		return result.Active.ReasonCode
	}
	return ""
}

func aggregateRuleReason(result *RuleLifecycleResult) LifecycleReasonCode {
	if result == nil {
		return ""
	}
	if result.ReasonCode != "" {
		return result.ReasonCode
	}
	if result.Active != nil {
		return result.Active.ReasonCode
	}
	return ""
}
