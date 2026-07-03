package networkenforcement

import (
	"context"
	"encoding/json"
)

const (
	ruleOperationPlan     = "plan_rules"
	ruleOperationApply    = "apply_rules"
	ruleOperationActive   = "active_rules"
	ruleOperationRollback = "rollback_rules"
	ruleOperationCleanup  = "cleanup_rules"
)

// RuleLifecycleAdapter is the narrow fakeable boundary for firewall/runtime
// rule lifecycle work. Implementations may own real rule state later, but this
// boundary exposes only sanitized metadata and errors are converted by the
// runner into safe codes and labels.
type RuleLifecycleAdapter interface {
	PlanNetworkRules(context.Context, RuleLifecycleRequest) (RuleLifecycleMetadata, error)
	ApplyNetworkRules(context.Context, RuleLifecycleRequest) (RuleLifecycleMetadata, error)
	ActiveNetworkRules(context.Context, RuleLifecycleRequest) (RuleLifecycleMetadata, error)
	RollbackNetworkRules(context.Context, RuleLifecycleRequest) (RuleLifecycleMetadata, error)
	CleanupNetworkRules(context.Context, RuleLifecycleRequest) (RuleLifecycleMetadata, error)
}

// RuleLifecycleRequest is passed to the adapter with a sanitized plan plus the
// runner's requested and current active rule state.
type RuleLifecycleRequest struct {
	Plan      SanitizedPlan
	Requested RuleLifecycleMetadata
	Active    RuleLifecycleMetadata
}

// RuleLifecycleRunner coordinates fake-testable firewall/runtime rule
// planning, application, active-state checks, rollback, and cleanup.
type RuleLifecycleRunner struct {
	Adapter RuleLifecycleAdapter
}

// RuleLifecycleResult preserves requested-vs-active rule state without
// exposing rule bodies, commands, addresses, ports, host paths, process
// details, credentials, or proxy listener details.
type RuleLifecycleResult struct {
	PlanID       string                 `json:"planId,omitempty"`
	AdapterID    string                 `json:"adapterId,omitempty"`
	Requested    *RuleLifecycleMetadata `json:"requested,omitempty"`
	Active       *RuleLifecycleMetadata `json:"active,omitempty"`
	Status       LifecycleStatus        `json:"status,omitempty"`
	ReasonCode   LifecycleReasonCode    `json:"reasonCode,omitempty"`
	WarningCodes []LifecycleWarningCode `json:"warningCodes,omitempty"`
}

// Apply plans and applies firewall/runtime rules, then asks the adapter to
// report active state. If apply or active-state reporting fails after partial
// mutation, the runner calls RollbackNetworkRules and reports rollback
// failures as warnings.
func (r RuleLifecycleRunner) Apply(ctx context.Context, plan Plan) (RuleLifecycleResult, error) {
	sanitizedPlan := NewSanitizedPlan(plan)
	input := sanitizedPlan.Plan()
	requested := requestedRuleLifecycle(input)
	result := RuleLifecycleResult{
		PlanID:    input.ID,
		Requested: &requested,
		Status:    LifecycleStatusRequested,
	}

	if r.Adapter == nil {
		failed := failedRuleLifecycle(input, requested, RuleLifecycleMetadata{}, ruleOperationPlan, LifecycleReasonAdapterUnsupported, nil)
		result = ruleLifecycleResultWithActive(result, failed, LifecycleReasonAdapterUnsupported)
		return SanitizeRuleLifecycleResult(result), ruleLifecycleError{operation: ruleOperationPlan, reason: LifecycleReasonAdapterUnsupported}
	}

	active := requested
	planned, err := r.Adapter.PlanNetworkRules(ctx, RuleLifecycleRequest{
		Plan:      sanitizedPlan,
		Requested: requested,
		Active:    active,
	})
	if err != nil {
		failed := failedRuleLifecycle(input, requested, planned, ruleOperationPlan, LifecycleReasonAdapterFailed, nil)
		result = ruleLifecycleResultWithActive(result, failed, LifecycleReasonAdapterFailed)
		return SanitizeRuleLifecycleResult(result), ruleLifecycleError{operation: ruleOperationPlan, reason: LifecycleReasonAdapterFailed}
	}
	active = completedRuleLifecycleStep(input, requested, planned, ruleOperationPlan, LifecycleStatusPlanned, LifecycleReasonPrepared)

	applied, err := r.Adapter.ApplyNetworkRules(ctx, RuleLifecycleRequest{
		Plan:      sanitizedPlan,
		Requested: requested,
		Active:    active,
	})
	if err != nil {
		failed := failedRuleLifecycle(input, requested, applied, ruleOperationApply, LifecycleReasonAdapterFailed, nil)
		failed.WarningCodes = appendLifecycleWarnings(failed.WarningCodes, r.rollbackAfterRuleFailure(ctx, sanitizedPlan, requested, failed)...)
		result = ruleLifecycleResultWithActive(result, failed, LifecycleReasonAdapterFailed)
		return SanitizeRuleLifecycleResult(result), ruleLifecycleError{operation: ruleOperationApply, reason: LifecycleReasonAdapterFailed}
	}
	active = completedRuleLifecycleStep(input, requested, applied, ruleOperationApply, LifecycleStatusApplying, LifecycleReasonApplied)

	checked, err := r.Adapter.ActiveNetworkRules(ctx, RuleLifecycleRequest{
		Plan:      sanitizedPlan,
		Requested: requested,
		Active:    active,
	})
	if err != nil {
		failed := failedRuleLifecycle(input, requested, checked, ruleOperationActive, LifecycleReasonActiveCheckFailed, nil)
		failed.WarningCodes = appendLifecycleWarnings(failed.WarningCodes, r.rollbackAfterRuleFailure(ctx, sanitizedPlan, requested, active)...)
		result = ruleLifecycleResultWithActive(result, failed, LifecycleReasonActiveCheckFailed)
		return SanitizeRuleLifecycleResult(result), ruleLifecycleError{operation: ruleOperationActive, reason: LifecycleReasonAdapterFailed, label: LifecycleReasonActiveCheckFailed}
	}
	active = completedRuleLifecycleStep(input, requested, checked, ruleOperationActive, LifecycleStatusActive, LifecycleReasonActive)
	result = ruleLifecycleResultWithActive(result, active, LifecycleReasonActive)
	return SanitizeRuleLifecycleResult(result), nil
}

// Cleanup asks the adapter to remove previously active firewall/runtime rules.
// Cleanup failures are warning metadata, not raw rule details or fatal public
// errors.
func (r RuleLifecycleRunner) Cleanup(ctx context.Context, plan Plan, active *RuleLifecycleMetadata) (RuleLifecycleResult, error) {
	sanitizedPlan := NewSanitizedPlan(plan)
	input := sanitizedPlan.Plan()
	requested := requestedRuleLifecycle(input)
	current := requested
	if active != nil {
		current = sanitizeRuleLifecycleOnlyMetadata(*active)
	}
	result := RuleLifecycleResult{
		PlanID:     input.ID,
		Requested:  &requested,
		Status:     LifecycleStatusStopped,
		ReasonCode: LifecycleReasonStopped,
	}

	if r.Adapter == nil {
		cleaned := completedRuleLifecycleStep(input, requested, current, ruleOperationCleanup, LifecycleStatusStopped, LifecycleReasonStopped)
		cleaned.WarningCodes = appendLifecycleWarnings(cleaned.WarningCodes, LifecycleWarningCleanupFailed, LifecycleWarningSanitizedAdapterError)
		result = ruleLifecycleResultWithActive(result, cleaned, LifecycleReasonStopped)
		return SanitizeRuleLifecycleResult(result), nil
	}

	cleaned, err := r.Adapter.CleanupNetworkRules(ctx, RuleLifecycleRequest{
		Plan:      sanitizedPlan,
		Requested: requested,
		Active:    current,
	})
	activeMetadata := completedRuleLifecycleStep(input, requested, cleaned, ruleOperationCleanup, LifecycleStatusStopped, LifecycleReasonStopped)
	if err != nil {
		activeMetadata.WarningCodes = appendLifecycleWarnings(nil, LifecycleWarningCleanupFailed, LifecycleWarningSanitizedAdapterError)
	}
	result = ruleLifecycleResultWithActive(result, activeMetadata, LifecycleReasonStopped)
	return SanitizeRuleLifecycleResult(result), nil
}

// SanitizeRuleLifecycleResult returns a redaction-safe rule lifecycle result
// copy.
func SanitizeRuleLifecycleResult(result RuleLifecycleResult) RuleLifecycleResult {
	sanitized := RuleLifecycleResult{
		PlanID:       sanitizeIdentifier(result.PlanID),
		AdapterID:    sanitizeIdentifier(result.AdapterID),
		Requested:    sanitizeRuleLifecycleOnlyMetadataPtr(result.Requested),
		Active:       sanitizeRuleLifecycleOnlyMetadataPtr(result.Active),
		Status:       sanitizeLifecycleStatus(result.Status),
		ReasonCode:   sanitizeLifecycleReasonCode(result.ReasonCode),
		WarningCodes: sanitizeLifecycleWarningCodeList(result.WarningCodes),
	}
	if sanitized.AdapterID == "" && sanitized.Active != nil {
		sanitized.AdapterID = sanitized.Active.AdapterID
	}
	if sanitized.AdapterID == "" && sanitized.Requested != nil {
		sanitized.AdapterID = sanitized.Requested.AdapterID
	}
	if sanitized.PlanID == "" && sanitized.Active != nil {
		sanitized.PlanID = sanitized.Active.PlanID
	}
	if sanitized.PlanID == "" && sanitized.Requested != nil {
		sanitized.PlanID = sanitized.Requested.PlanID
	}
	return sanitized
}

func (r RuleLifecycleResult) MarshalJSON() ([]byte, error) {
	type ruleLifecycleResultJSON RuleLifecycleResult
	sanitized := SanitizeRuleLifecycleResult(r)
	return json.Marshal(ruleLifecycleResultJSON(sanitized))
}

type ruleLifecycleError struct {
	operation string
	reason    LifecycleReasonCode
	label     LifecycleReasonCode
}

func (e ruleLifecycleError) Error() string {
	operation := sanitizeIdentifier(e.operation)
	reason := sanitizeLifecycleReasonCode(e.reason)
	label := sanitizeLifecycleReasonCode(e.label)
	if operation == "" {
		operation = "lifecycle"
	}
	if reason == "" {
		reason = LifecycleReasonAdapterFailed
	}
	message := "network rule lifecycle " + operation + " " + string(reason)
	if label != "" && label != reason {
		message += " " + string(label)
	}
	return message
}

func (r RuleLifecycleRunner) rollbackAfterRuleFailure(ctx context.Context, plan SanitizedPlan, requested, active RuleLifecycleMetadata) []LifecycleWarningCode {
	if r.Adapter == nil {
		return []LifecycleWarningCode{LifecycleWarningRollbackFailed, LifecycleWarningSanitizedAdapterError}
	}
	_, err := r.Adapter.RollbackNetworkRules(ctx, RuleLifecycleRequest{
		Plan:      plan,
		Requested: requested,
		Active:    active,
	})
	if err == nil {
		return nil
	}
	return []LifecycleWarningCode{LifecycleWarningRollbackFailed}
}

func requestedRuleLifecycle(plan Plan) RuleLifecycleMetadata {
	metadata := RuleLifecycleMetadata{
		PlanID:         plan.ID,
		Status:         LifecycleStatusRequested,
		Mechanisms:     []EnforcementMechanism{EnforcementMechanismFirewall},
		PolicySnapshot: plan.PolicySnapshot,
	}
	if plan.PolicySnapshot != nil {
		metadata.ID = plan.PolicySnapshot.RuleSetID
	}
	if metadata.ID == "" && plan.Allowlist != nil {
		metadata.ID = plan.Allowlist.RuleSetID
	}
	if plan.Firewall != nil {
		metadata.Operations = append([]string(nil), plan.Firewall.Operations...)
		if mechanism := sanitizeRuleLifecycleMechanism(plan.Firewall.Mechanism); mechanism != "" {
			metadata.Mechanisms = []EnforcementMechanism{mechanism}
		}
	}
	return sanitizeRuleLifecycleOnlyMetadata(metadata)
}

func completedRuleLifecycleStep(plan Plan, requested, adapterMetadata RuleLifecycleMetadata, operation string, status LifecycleStatus, reason LifecycleReasonCode) RuleLifecycleMetadata {
	metadata := sanitizeRuleLifecycleOnlyMetadata(adapterMetadata)
	if metadata.ID == "" {
		metadata.ID = requested.ID
	}
	if metadata.PlanID == "" {
		metadata.PlanID = plan.ID
	}
	if metadata.Status == "" || metadata.Status == LifecycleStatusFailed {
		metadata.Status = status
	}
	if len(metadata.Mechanisms) == 0 {
		metadata.Mechanisms = append([]EnforcementMechanism(nil), requested.Mechanisms...)
	}
	metadata.Operations = []string{operation}
	if metadata.PolicySnapshot == nil {
		metadata.PolicySnapshot = sanitizePolicySnapshotIdentityPtr(plan.PolicySnapshot)
	}
	metadata.ReasonCode = reason
	return sanitizeRuleLifecycleOnlyMetadata(metadata)
}

func failedRuleLifecycle(plan Plan, requested, adapterMetadata RuleLifecycleMetadata, operation string, reason LifecycleReasonCode, warnings []LifecycleWarningCode) RuleLifecycleMetadata {
	metadata := completedRuleLifecycleStep(plan, requested, adapterMetadata, operation, LifecycleStatusFailed, reason)
	metadata.Status = LifecycleStatusFailed
	metadata.ReasonCode = reason
	metadata.WarningCodes = appendLifecycleWarnings(metadata.WarningCodes, LifecycleWarningSanitizedAdapterError)
	metadata.WarningCodes = appendLifecycleWarnings(metadata.WarningCodes, warnings...)
	return sanitizeRuleLifecycleOnlyMetadata(metadata)
}

func ruleLifecycleResultWithActive(result RuleLifecycleResult, active RuleLifecycleMetadata, reason LifecycleReasonCode) RuleLifecycleResult {
	active = sanitizeRuleLifecycleOnlyMetadata(active)
	result.Active = &active
	result.AdapterID = active.AdapterID
	result.Status = active.Status
	result.ReasonCode = reason
	result.WarningCodes = appendLifecycleWarnings(result.WarningCodes, active.WarningCodes...)
	return SanitizeRuleLifecycleResult(result)
}

func sanitizeRuleLifecycleOnlyMetadataPtr(metadata *RuleLifecycleMetadata) *RuleLifecycleMetadata {
	if metadata == nil {
		return nil
	}
	sanitized := sanitizeRuleLifecycleOnlyMetadata(*metadata)
	if ruleLifecycleMetadataEmpty(sanitized) {
		return nil
	}
	return &sanitized
}

func sanitizeRuleLifecycleOnlyMetadata(metadata RuleLifecycleMetadata) RuleLifecycleMetadata {
	sanitized := SanitizeRuleLifecycleMetadata(metadata)
	sanitized.Mechanisms = sanitizeRuleLifecycleMechanisms(sanitized.Mechanisms)
	sanitized.CapabilityLabels = sanitizeRuleLifecycleCapabilityLabels(sanitized.CapabilityLabels)
	return sanitized
}

func sanitizeRuleLifecycleMechanisms(values []EnforcementMechanism) []EnforcementMechanism {
	if len(values) == 0 {
		return nil
	}
	sanitized := make([]EnforcementMechanism, 0, len(values))
	for _, value := range values {
		current := sanitizeRuleLifecycleMechanism(value)
		if current == "" || ruleLifecycleMechanismContains(sanitized, current) {
			continue
		}
		sanitized = append(sanitized, current)
	}
	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
}

func sanitizeRuleLifecycleMechanism(value EnforcementMechanism) EnforcementMechanism {
	switch sanitizeEnforcementMechanism(value) {
	case EnforcementMechanismFirewall:
		return EnforcementMechanismFirewall
	case EnforcementMechanismRuntime:
		return EnforcementMechanismRuntime
	default:
		return ""
	}
}

func ruleLifecycleMechanismContains(values []EnforcementMechanism, target EnforcementMechanism) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func sanitizeRuleLifecycleCapabilityLabels(labels []string) []string {
	if len(labels) == 0 {
		return nil
	}
	sanitized := make([]string, 0, len(labels))
	for _, label := range labels {
		current := sanitizeIdentifier(label)
		if current == "" {
			continue
		}
		lower := normalizeEnum(current)
		if containsLifecycleLabelFragment(lower, "proxy") ||
			containsLifecycleLabelFragment(lower, "listener") ||
			containsLifecycleLabelFragment(lower, "process") {
			continue
		}
		sanitized = append(sanitized, current)
	}
	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
}
