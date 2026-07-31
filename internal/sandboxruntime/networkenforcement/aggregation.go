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

// LiveEnforcementRun carries the aggregated adapter result plus sanitized
// lifecycle proof for status projections that need active proxy/rule metadata.
type LiveEnforcementRun struct {
	Result    Result
	Lifecycle LiveLifecycleMetadata
}

// EnforceNetwork implements Adapter using the live lifecycle runners. The
// orchestration remains fake-only: concrete listener, firewall, or runtime
// mutation can only happen behind injected lifecycle adapters.
func (r LiveEnforcementRunner) EnforceNetwork(ctx context.Context, plan SanitizedPlan) Result {
	return r.EnforceNetworkWithLifecycle(ctx, plan).Result
}

// EnforceNetworkWithLifecycle coordinates the same live lifecycle work as
// EnforceNetwork while retaining the sanitized proxy/rule proof that command
// and worker status projections consume later.
func (r LiveEnforcementRunner) EnforceNetworkWithLifecycle(ctx context.Context, plan SanitizedPlan) LiveEnforcementRun {
	input := plan.Plan()
	listener, listenerErr := r.Listener.Start(ctx, input)
	if listenerErr != nil {
		result := AggregateLiveEnforcementResult(input, &listener, nil)
		return liveEnforcementRun(input, result, &listener, nil)
	}

	rules, ruleErr := r.Rules.Apply(ctx, input)
	if ruleErr != nil {
		stopped, _ := r.Listener.Stop(ctx, input, listener.Active)
		listener = aggregateListenerCleanupWarnings(listener, stopped)
		result := AggregateLiveEnforcementResult(input, &listener, &rules)
		return liveEnforcementRun(input, result, &listener, &rules)
	}

	result := AggregateLiveEnforcementResult(input, &listener, &rules)
	return liveEnforcementRun(input, result, &listener, &rules)
}

// AggregateLiveEnforcementResult combines sanitized listener and
// firewall/runtime rule lifecycle metadata into the adapter Result contract.
// Requested or planned metadata alone never upgrades to strong enforcement.
func AggregateLiveEnforcementResult(plan Plan, listener *ProxyListenerLifecycleResult, rules *RuleLifecycleResult) Result {
	input := SanitizePlan(plan)
	listenerResult := sanitizeAggregateListenerResult(listener)
	ruleResult := sanitizeAggregateRuleResult(rules)

	mechanisms := aggregateResultMechanisms(input, listenerResult, ruleResult)
	operations := aggregateResultOperations(listenerResult, ruleResult)
	policySnapshot := sanitizePolicySnapshotIdentityPtr(input.PolicySnapshot)
	strongCandidate := aggregatePlanAllowsStrongEnforcement(input) &&
		aggregateListenerActive(listenerResult) &&
		aggregateRulesLifecycleActive(ruleResult)
	strongLifecycle := strongCandidate &&
		aggregateRulesActive(ruleResult) &&
		aggregateProofCorrelatedWithPlan(input, listenerResult, ruleResult)
	strongMode := ResultModeNone
	strongCapabilityCompatible := false
	if strongLifecycle {
		strongMode = aggregateStrongResultMode(ruleResult)
		strongCapabilityCompatible = resultModeCanEnforce(strongMode) &&
			aggregateRuleCapabilityCompatibleWithPlan(input, ruleResult)
	}
	warnings := aggregateResultWarnings(listenerResult, ruleResult)
	if strongCandidate && (!strongLifecycle || !resultModeCanEnforce(strongMode) || !strongCapabilityCompatible) {
		warnings = appendResultWarnings(warnings, ResultWarningCapabilityDowngraded)
	}

	if strongLifecycle && strongCapabilityCompatible {
		return SanitizeResult(Result{
			PlanID:          input.ID,
			AdapterID:       liveEnforcementAggregationAdapterID,
			Outcome:         ResultOutcomeSuccess,
			EnforcementMode: strongMode,
			Mechanisms:      mechanisms,
			Operations:      operations,
			PolicySnapshot:  policySnapshot,
			Capability:      aggregateResultCapability(input, strongMode),
			ReasonCode:      ResultReasonApplied,
			WarningCodes:    warnings,
		})
	}

	if aggregateBestEffortPlan(input) &&
		aggregateListenerActive(listenerResult) &&
		aggregateRulesLifecycleActive(ruleResult) {
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

func liveEnforcementRun(plan Plan, result Result, listener *ProxyListenerLifecycleResult, rules *RuleLifecycleResult) LiveEnforcementRun {
	result = SanitizeResult(result)
	if result.PlanID == "" {
		result.PlanID = SanitizePlan(plan).ID
	}
	lifecycle := liveLifecycleMetadataFromRun(plan, result, listener, rules)
	return LiveEnforcementRun{
		Result:    SanitizeResult(result),
		Lifecycle: lifecycle,
	}
}

func liveLifecycleMetadataFromRun(plan Plan, result Result, listener *ProxyListenerLifecycleResult, rules *RuleLifecycleResult) LiveLifecycleMetadata {
	input := SanitizePlan(plan)
	result = SanitizeResult(result)
	policySnapshot := result.PolicySnapshot
	if policySnapshot == nil {
		policySnapshot = input.PolicySnapshot
	}
	metadata := LiveLifecycleMetadata{
		PlanID:         liveLifecyclePlanID(input, result),
		AdapterID:      result.AdapterID,
		Status:         liveLifecycleStatusFromResult(result),
		Mechanisms:     liveLifecycleMechanisms(input, result),
		Operations:     sanitizeIdentifierList(result.Operations),
		PolicySnapshot: policySnapshot,
		Proxy:          liveLifecycleProxyMetadata(listener),
		Rules:          liveLifecycleRuleMetadata(rules),
		ReasonCode:     liveLifecycleReasonFromResult(result),
		WarningCodes:   liveLifecycleWarningsFromResult(result.WarningCodes),
	}
	metadata.CapabilityLabels = liveLifecycleCapabilityLabels(metadata.Proxy, metadata.Rules)
	return SanitizeLiveLifecycleMetadata(metadata)
}

func liveLifecyclePlanID(plan Plan, result Result) string {
	if result.PlanID != "" {
		return result.PlanID
	}
	return plan.ID
}

func liveLifecycleStatusFromResult(result Result) LifecycleStatus {
	switch result.Outcome {
	case ResultOutcomeSuccess:
		if resultModeCanEnforce(result.EnforcementMode) {
			return LifecycleStatusActive
		}
		return LifecycleStatusFailed
	case ResultOutcomeBestEffort:
		return LifecycleStatusActive
	case ResultOutcomeUnsupported, ResultOutcomeFailure:
		return LifecycleStatusFailed
	default:
		return LifecycleStatusFailed
	}
}

func liveLifecycleReasonFromResult(result Result) LifecycleReasonCode {
	switch result.ReasonCode {
	case ResultReasonApplied:
		return LifecycleReasonActive
	case ResultReasonAdapterUnsupported:
		return LifecycleReasonAdapterUnsupported
	case ResultReasonCapabilityMissing, ResultReasonModeUnavailable:
		return LifecycleReasonCapabilityMissing
	case ResultReasonAdapterFailed:
		return LifecycleReasonAdapterFailed
	case ResultReasonBestEffort:
		return LifecycleReasonPrepared
	default:
		return ""
	}
}

func liveLifecycleWarningsFromResult(values []ResultWarningCode) []LifecycleWarningCode {
	var warnings []LifecycleWarningCode
	for _, value := range sanitizeResultWarningCodeList(values) {
		switch value {
		case ResultWarningPartialEnforcement, ResultWarningCapabilityDowngraded:
			warnings = appendLifecycleWarnings(warnings, LifecycleWarningPartialLifecycle)
		case ResultWarningUnsupportedMode:
			warnings = appendLifecycleWarnings(warnings, LifecycleWarningUnsupportedMechanism)
		case ResultWarningMetadataOnlyFallback:
			warnings = appendLifecycleWarnings(warnings, LifecycleWarningMetadataOnlyFallback)
		case ResultWarningSanitizedAdapterError:
			warnings = appendLifecycleWarnings(warnings, LifecycleWarningSanitizedAdapterError)
		}
	}
	return warnings
}

func liveLifecycleMechanisms(plan Plan, result Result) []EnforcementMechanism {
	mechanisms := sanitizeEnforcementMechanismList(result.Mechanisms)
	if len(mechanisms) > 0 {
		return mechanisms
	}
	return aggregateResultMechanisms(plan, nil, nil)
}

func liveLifecycleProxyMetadata(listener *ProxyListenerLifecycleResult) *ProxyListenerLifecycleMetadata {
	if listener == nil {
		return nil
	}
	if listener.Active != nil {
		metadata := sanitizeProxyListenerOnlyMetadata(*listener.Active)
		if !proxyListenerLifecycleMetadataEmpty(metadata) {
			return &metadata
		}
	}
	if listener.Requested != nil {
		metadata := sanitizeProxyListenerOnlyMetadata(*listener.Requested)
		if !proxyListenerLifecycleMetadataEmpty(metadata) {
			return &metadata
		}
	}
	return nil
}

func liveLifecycleRuleMetadata(rules *RuleLifecycleResult) []RuleLifecycleMetadata {
	if rules == nil {
		return nil
	}
	if rules.Active != nil {
		metadata := sanitizeRuleLifecycleOnlyMetadata(*rules.Active)
		if !ruleLifecycleMetadataEmpty(metadata) {
			return []RuleLifecycleMetadata{metadata}
		}
	}
	if rules.Requested != nil {
		metadata := sanitizeRuleLifecycleOnlyMetadata(*rules.Requested)
		if !ruleLifecycleMetadataEmpty(metadata) {
			return []RuleLifecycleMetadata{metadata}
		}
	}
	return nil
}

func liveLifecycleCapabilityLabels(proxy *ProxyListenerLifecycleMetadata, rules []RuleLifecycleMetadata) []string {
	var labels []string
	if proxy != nil {
		labels = appendSanitizedIdentifiers(labels, proxy.CapabilityLabels...)
	}
	for _, rule := range rules {
		labels = appendSanitizedIdentifiers(labels, rule.CapabilityLabels...)
	}
	return sanitizeIdentifierList(labels)
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
		result.Active.Correlation != nil &&
		EnforcementCorrelationComplete(*result.Active.Correlation) &&
		len(result.Active.WarningCodes) == 0
}

func aggregateRulesActive(result *RuleLifecycleResult) bool {
	if !aggregateRulesLifecycleActive(result) {
		return false
	}
	proof := sanitizeInspectedRuleProofPtr(result.Active.Inspection)
	return proof != nil &&
		proof.Status == RuleInspectionStatusInspected &&
		proof.ReasonCode == LifecycleReasonRuleInspected &&
		len(proof.WarningCodes) == 0 &&
		result.Active.Correlation != nil &&
		EnforcementCorrelationComplete(*result.Active.Correlation)
}

func aggregateRulesLifecycleActive(result *RuleLifecycleResult) bool {
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

func aggregateProofCorrelatedWithPlan(plan Plan, listener *ProxyListenerLifecycleResult, rules *RuleLifecycleResult) bool {
	if listener == nil || listener.Active == nil || listener.Active.Correlation == nil ||
		rules == nil || rules.Active == nil || rules.Active.Correlation == nil ||
		rules.Active.Inspection == nil || rules.Active.Inspection.Correlation == nil {
		return false
	}
	listenerCorrelation := *listener.Active.Correlation
	ruleCorrelation := *rules.Active.Correlation
	proofCorrelation := *rules.Active.Inspection.Correlation
	if !EnforcementCorrelationsEqual(listenerCorrelation, ruleCorrelation) ||
		!EnforcementCorrelationsEqual(ruleCorrelation, proofCorrelation) {
		return false
	}
	if listenerCorrelation.PlanID != plan.ID || plan.PolicySnapshot == nil ||
		listenerCorrelation.PolicySnapshotID != plan.PolicySnapshot.ID ||
		plan.Proxy == nil || listenerCorrelation.ProxySessionID != plan.Proxy.ProxySessionID {
		return false
	}
	return true
}

func aggregateStrongResultMode(rules *RuleLifecycleResult) ResultMode {
	if rules == nil || rules.Active == nil || rules.Active.Inspection == nil {
		return ResultModeNone
	}
	for _, mechanism := range rules.Active.Inspection.Mechanisms {
		switch mechanism {
		case EnforcementMechanismFirewall:
			return ResultModeProxyFirewall
		case EnforcementMechanismRuntime:
			return ResultModeRuntime
		}
	}
	return ResultModeNone
}

func aggregateRuleCapabilityCompatibleWithPlan(plan Plan, rules *RuleLifecycleResult) bool {
	if rules == nil || rules.Active == nil || rules.Active.Inspection == nil {
		return false
	}
	labels := sanitizeIdentifierList(rules.Active.Inspection.CapabilityLabels)
	if plan.DefaultPosture == DefaultPostureDenyByDefault &&
		!aggregateRuleCapabilityHasAnyLabel(labels, planOperationDefaultDeny, "default_deny_active") {
		return false
	}
	if plan.Allowlist != nil {
		for _, category := range plan.Allowlist.RuleCategories {
			if category == AllowlistRuleCategoryDomain || category == AllowlistRuleCategoryEndpoint {
				continue
			}
			if !aggregateRuleCapabilitySupportsCategory(labels, category) {
				return false
			}
		}
	}
	if plan.Category != nil {
		if plan.Category.PrivateNetwork == PostureBlock &&
			!aggregateRuleCapabilityHasAnyLabel(labels, "private_range_rules", planOperationAllowlistPrivateRange, planOperationBlockPrivateNetwork) {
			return false
		}
		if plan.Category.MetadataEndpoint == PostureBlock &&
			!aggregateRuleCapabilityHasAnyLabel(labels, "metadata_endpoint", "metadata_endpoint_rules", planOperationAllowlistMetadata, planOperationBlockMetadataEndpoint) {
			return false
		}
	}
	if plan.RawProtocols != nil &&
		(plan.RawProtocols.TCP == PostureBlock || plan.RawProtocols.UDP == PostureBlock || plan.RawProtocols.ICMP == PostureBlock) &&
		!aggregateRuleCapabilityHasAnyLabel(labels, "raw_protocols", planOperationBlockRawProtocols) {
		return false
	}
	return true
}

func aggregateRuleCapabilitySupportsCategory(labels []string, category AllowlistRuleCategory) bool {
	switch category {
	case AllowlistRuleCategoryDomain:
		return aggregateRuleCapabilityHasAnyLabel(labels, "domain_rules", planOperationAllowlistDomain)
	case AllowlistRuleCategoryEndpoint:
		return aggregateRuleCapabilityHasAnyLabel(labels, "endpoint_rules", planOperationAllowlistEndpoint)
	case AllowlistRuleCategoryPrivateRange:
		return aggregateRuleCapabilityHasAnyLabel(labels, "private_range_rules", planOperationAllowlistPrivateRange, planOperationBlockPrivateNetwork)
	case AllowlistRuleCategoryMetadataEndpoint:
		return aggregateRuleCapabilityHasAnyLabel(labels, "metadata_endpoint", "metadata_endpoint_rules", planOperationAllowlistMetadata, planOperationBlockMetadataEndpoint)
	case AllowlistRuleCategoryLoopback:
		return aggregateRuleCapabilityHasAnyLabel(labels, "loopback_rules", planOperationAllowlistLoopback)
	case AllowlistRuleCategoryLinkLocal:
		return aggregateRuleCapabilityHasAnyLabel(labels, "link_local_rules", planOperationAllowlistLinkLocal)
	default:
		return false
	}
}

func aggregateRuleCapabilityHasAnyLabel(labels []string, candidates ...string) bool {
	for _, candidate := range candidates {
		current := sanitizeIdentifier(candidate)
		if current == "" {
			continue
		}
		for _, label := range labels {
			if label == current {
				return true
			}
		}
	}
	return false
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
