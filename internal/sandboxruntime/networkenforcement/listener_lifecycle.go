package networkenforcement

import (
	"context"
	"encoding/json"
)

const (
	proxyListenerOperationPrepare = "prepare_proxy"
	proxyListenerOperationStart   = "start_proxy"
	proxyListenerOperationActive  = "active_proxy"
	proxyListenerOperationStop    = "stop_proxy"
)

// ProxyListenerAdapter is the narrow fakeable boundary for proxy listener
// lifecycle work. Implementations may own real listener state later, but this
// boundary exposes only sanitized metadata and errors are converted by the
// runner into safe codes and labels.
type ProxyListenerAdapter interface {
	PrepareProxyListener(context.Context, ProxyListenerLifecycleRequest) (ProxyListenerLifecycleMetadata, error)
	StartProxyListener(context.Context, ProxyListenerLifecycleRequest) (ProxyListenerLifecycleMetadata, error)
	ActiveProxyListener(context.Context, ProxyListenerLifecycleRequest) (ProxyListenerLifecycleMetadata, error)
	StopProxyListener(context.Context, ProxyListenerLifecycleRequest) (ProxyListenerLifecycleMetadata, error)
}

// ProxyListenerLifecycleRequest is passed to the adapter with a sanitized plan
// plus the runner's requested and current active state.
type ProxyListenerLifecycleRequest struct {
	Plan      SanitizedPlan
	Requested ProxyListenerLifecycleMetadata
	Active    ProxyListenerLifecycleMetadata
}

// ProxyListenerLifecycleRunner coordinates fake-testable proxy listener
// prepare, start, active-state, and stop operations.
type ProxyListenerLifecycleRunner struct {
	Adapter ProxyListenerAdapter
}

// ProxyListenerLifecycleResult preserves requested-vs-active listener state
// without exposing listener endpoints, sockets, processes, destinations, or
// non-proxy enforcement claims.
type ProxyListenerLifecycleResult struct {
	PlanID       string                          `json:"planId,omitempty"`
	AdapterID    string                          `json:"adapterId,omitempty"`
	Requested    *ProxyListenerLifecycleMetadata `json:"requested,omitempty"`
	Active       *ProxyListenerLifecycleMetadata `json:"active,omitempty"`
	Status       LifecycleStatus                 `json:"status,omitempty"`
	ReasonCode   LifecycleReasonCode             `json:"reasonCode,omitempty"`
	WarningCodes []LifecycleWarningCode          `json:"warningCodes,omitempty"`
}

// Start prepares and starts a proxy listener, then asks the adapter to report
// active state. If start or active-state reporting fails after partial setup,
// the runner calls StopProxyListener and reports cleanup failures as warnings.
func (r ProxyListenerLifecycleRunner) Start(ctx context.Context, plan Plan) (ProxyListenerLifecycleResult, error) {
	sanitizedPlan := NewSanitizedPlan(plan)
	input := sanitizedPlan.Plan()
	requested := requestedProxyListenerLifecycle(input)
	result := ProxyListenerLifecycleResult{
		PlanID:    input.ID,
		Requested: &requested,
		Status:    LifecycleStatusRequested,
	}

	if r.Adapter == nil {
		failed := failedProxyListenerLifecycle(input, requested, ProxyListenerLifecycleMetadata{}, proxyListenerOperationPrepare, LifecycleReasonAdapterUnsupported, nil)
		result = proxyListenerLifecycleResultWithActive(result, failed, LifecycleReasonAdapterUnsupported)
		return SanitizeProxyListenerLifecycleResult(result), proxyListenerLifecycleError{operation: proxyListenerOperationPrepare, reason: LifecycleReasonAdapterUnsupported}
	}

	active := requested
	prepared, err := r.Adapter.PrepareProxyListener(ctx, ProxyListenerLifecycleRequest{
		Plan:      sanitizedPlan,
		Requested: requested,
		Active:    active,
	})
	if err != nil {
		failed := failedProxyListenerLifecycle(input, requested, prepared, proxyListenerOperationPrepare, LifecycleReasonAdapterFailed, nil)
		result = proxyListenerLifecycleResultWithActive(result, failed, LifecycleReasonAdapterFailed)
		return SanitizeProxyListenerLifecycleResult(result), proxyListenerLifecycleError{operation: proxyListenerOperationPrepare, reason: LifecycleReasonAdapterFailed}
	}
	active = completedProxyListenerLifecycleStep(input, requested, prepared, proxyListenerOperationPrepare, LifecycleStatusPrepared, LifecycleReasonPrepared)

	started, err := r.Adapter.StartProxyListener(ctx, ProxyListenerLifecycleRequest{
		Plan:      sanitizedPlan,
		Requested: requested,
		Active:    active,
	})
	if err != nil {
		failed := failedProxyListenerLifecycle(input, requested, started, proxyListenerOperationStart, LifecycleReasonAdapterFailed, nil)
		failed.WarningCodes = appendLifecycleWarnings(failed.WarningCodes, r.stopAfterProxyListenerFailure(ctx, sanitizedPlan, requested, active)...)
		result = proxyListenerLifecycleResultWithActive(result, failed, LifecycleReasonAdapterFailed)
		return SanitizeProxyListenerLifecycleResult(result), proxyListenerLifecycleError{operation: proxyListenerOperationStart, reason: LifecycleReasonAdapterFailed}
	}
	active = completedProxyListenerLifecycleStep(input, requested, started, proxyListenerOperationStart, LifecycleStatusStarting, LifecycleReasonStarted)

	checked, err := r.Adapter.ActiveProxyListener(ctx, ProxyListenerLifecycleRequest{
		Plan:      sanitizedPlan,
		Requested: requested,
		Active:    active,
	})
	if err != nil {
		failed := failedProxyListenerLifecycle(input, requested, checked, proxyListenerOperationActive, LifecycleReasonActiveCheckFailed, nil)
		failed.WarningCodes = appendLifecycleWarnings(failed.WarningCodes, r.stopAfterProxyListenerFailure(ctx, sanitizedPlan, requested, active)...)
		result = proxyListenerLifecycleResultWithActive(result, failed, LifecycleReasonActiveCheckFailed)
		return SanitizeProxyListenerLifecycleResult(result), proxyListenerLifecycleError{operation: proxyListenerOperationActive, reason: LifecycleReasonAdapterFailed, label: LifecycleReasonActiveCheckFailed}
	}
	active = completedProxyListenerLifecycleStep(input, requested, checked, proxyListenerOperationActive, LifecycleStatusActive, LifecycleReasonActive)
	result = proxyListenerLifecycleResultWithActive(result, active, LifecycleReasonActive)
	return SanitizeProxyListenerLifecycleResult(result), nil
}

// Stop asks the adapter to stop a previously active proxy listener. Stop
// failures are warning metadata, not raw listener details or fatal public
// errors.
func (r ProxyListenerLifecycleRunner) Stop(ctx context.Context, plan Plan, active *ProxyListenerLifecycleMetadata) (ProxyListenerLifecycleResult, error) {
	sanitizedPlan := NewSanitizedPlan(plan)
	input := sanitizedPlan.Plan()
	requested := requestedProxyListenerLifecycle(input)
	current := requested
	if active != nil {
		current = sanitizeProxyListenerOnlyMetadata(*active)
	}
	result := ProxyListenerLifecycleResult{
		PlanID:     input.ID,
		Requested:  &requested,
		Status:     LifecycleStatusStopped,
		ReasonCode: LifecycleReasonStopped,
	}

	if r.Adapter == nil {
		stopped := completedProxyListenerLifecycleStep(input, requested, current, proxyListenerOperationStop, LifecycleStatusStopped, LifecycleReasonStopped)
		stopped.WarningCodes = appendLifecycleWarnings(stopped.WarningCodes, LifecycleWarningCleanupFailed, LifecycleWarningSanitizedAdapterError)
		result = proxyListenerLifecycleResultWithActive(result, stopped, LifecycleReasonStopped)
		return SanitizeProxyListenerLifecycleResult(result), nil
	}

	stopped, err := r.Adapter.StopProxyListener(ctx, ProxyListenerLifecycleRequest{
		Plan:      sanitizedPlan,
		Requested: requested,
		Active:    current,
	})
	activeMetadata := completedProxyListenerLifecycleStep(input, requested, stopped, proxyListenerOperationStop, LifecycleStatusStopped, LifecycleReasonStopped)
	if err != nil {
		activeMetadata.WarningCodes = appendLifecycleWarnings(nil, LifecycleWarningCleanupFailed, LifecycleWarningSanitizedAdapterError)
	}
	result = proxyListenerLifecycleResultWithActive(result, activeMetadata, LifecycleReasonStopped)
	return SanitizeProxyListenerLifecycleResult(result), nil
}

// SanitizeProxyListenerLifecycleResult returns a redaction-safe proxy listener
// lifecycle result copy.
func SanitizeProxyListenerLifecycleResult(result ProxyListenerLifecycleResult) ProxyListenerLifecycleResult {
	sanitized := ProxyListenerLifecycleResult{
		PlanID:       sanitizeIdentifier(result.PlanID),
		AdapterID:    sanitizeIdentifier(result.AdapterID),
		Requested:    sanitizeProxyListenerOnlyMetadataPtr(result.Requested),
		Active:       sanitizeProxyListenerOnlyMetadataPtr(result.Active),
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

func (r ProxyListenerLifecycleResult) MarshalJSON() ([]byte, error) {
	type proxyListenerLifecycleResultJSON ProxyListenerLifecycleResult
	sanitized := SanitizeProxyListenerLifecycleResult(r)
	return json.Marshal(proxyListenerLifecycleResultJSON(sanitized))
}

type proxyListenerLifecycleError struct {
	operation string
	reason    LifecycleReasonCode
	label     LifecycleReasonCode
}

func (e proxyListenerLifecycleError) Error() string {
	operation := sanitizeIdentifier(e.operation)
	reason := sanitizeLifecycleReasonCode(e.reason)
	label := sanitizeLifecycleReasonCode(e.label)
	if operation == "" {
		operation = "lifecycle"
	}
	if reason == "" {
		reason = LifecycleReasonAdapterFailed
	}
	message := "network proxy listener lifecycle " + operation + " " + string(reason)
	if label != "" && label != reason {
		message += " " + string(label)
	}
	return message
}

func (r ProxyListenerLifecycleRunner) stopAfterProxyListenerFailure(ctx context.Context, plan SanitizedPlan, requested, active ProxyListenerLifecycleMetadata) []LifecycleWarningCode {
	if r.Adapter == nil {
		return []LifecycleWarningCode{LifecycleWarningCleanupFailed, LifecycleWarningSanitizedAdapterError}
	}
	_, err := r.Adapter.StopProxyListener(ctx, ProxyListenerLifecycleRequest{
		Plan:      plan,
		Requested: requested,
		Active:    active,
	})
	if err == nil {
		return nil
	}
	return []LifecycleWarningCode{LifecycleWarningCleanupFailed}
}

func requestedProxyListenerLifecycle(plan Plan) ProxyListenerLifecycleMetadata {
	metadata := ProxyListenerLifecycleMetadata{
		PlanID:         plan.ID,
		Status:         LifecycleStatusRequested,
		Mechanisms:     []EnforcementMechanism{EnforcementMechanismProxy},
		PolicySnapshot: plan.PolicySnapshot,
	}
	if plan.Proxy != nil {
		metadata.ID = plan.Proxy.ProxySessionID
		metadata.Operations = append([]string(nil), plan.Proxy.Operations...)
		if plan.Proxy.Mechanism == EnforcementMechanismProxy {
			metadata.Mechanisms = []EnforcementMechanism{EnforcementMechanismProxy}
		}
	}
	return sanitizeProxyListenerOnlyMetadata(metadata)
}

func completedProxyListenerLifecycleStep(plan Plan, requested, adapterMetadata ProxyListenerLifecycleMetadata, operation string, status LifecycleStatus, reason LifecycleReasonCode) ProxyListenerLifecycleMetadata {
	metadata := sanitizeProxyListenerOnlyMetadata(adapterMetadata)
	if metadata.ID == "" {
		metadata.ID = requested.ID
	}
	if metadata.PlanID == "" {
		metadata.PlanID = plan.ID
	}
	if metadata.Status == "" || metadata.Status == LifecycleStatusFailed {
		metadata.Status = status
	}
	metadata.Mechanisms = []EnforcementMechanism{EnforcementMechanismProxy}
	metadata.Operations = []string{operation}
	if metadata.PolicySnapshot == nil {
		metadata.PolicySnapshot = sanitizePolicySnapshotIdentityPtr(plan.PolicySnapshot)
	}
	metadata.ReasonCode = reason
	return sanitizeProxyListenerOnlyMetadata(metadata)
}

func failedProxyListenerLifecycle(plan Plan, requested, adapterMetadata ProxyListenerLifecycleMetadata, operation string, reason LifecycleReasonCode, warnings []LifecycleWarningCode) ProxyListenerLifecycleMetadata {
	metadata := completedProxyListenerLifecycleStep(plan, requested, adapterMetadata, operation, LifecycleStatusFailed, reason)
	metadata.Status = LifecycleStatusFailed
	metadata.ReasonCode = reason
	metadata.WarningCodes = appendLifecycleWarnings(metadata.WarningCodes, LifecycleWarningSanitizedAdapterError)
	metadata.WarningCodes = appendLifecycleWarnings(metadata.WarningCodes, warnings...)
	return sanitizeProxyListenerOnlyMetadata(metadata)
}

func proxyListenerLifecycleResultWithActive(result ProxyListenerLifecycleResult, active ProxyListenerLifecycleMetadata, reason LifecycleReasonCode) ProxyListenerLifecycleResult {
	active = sanitizeProxyListenerOnlyMetadata(active)
	result.Active = &active
	result.AdapterID = active.AdapterID
	result.Status = active.Status
	result.ReasonCode = reason
	result.WarningCodes = appendLifecycleWarnings(result.WarningCodes, active.WarningCodes...)
	return SanitizeProxyListenerLifecycleResult(result)
}

func sanitizeProxyListenerOnlyMetadataPtr(metadata *ProxyListenerLifecycleMetadata) *ProxyListenerLifecycleMetadata {
	if metadata == nil {
		return nil
	}
	sanitized := sanitizeProxyListenerOnlyMetadata(*metadata)
	if proxyListenerLifecycleMetadataEmpty(sanitized) {
		return nil
	}
	return &sanitized
}

func sanitizeProxyListenerOnlyMetadata(metadata ProxyListenerLifecycleMetadata) ProxyListenerLifecycleMetadata {
	sanitized := SanitizeProxyListenerLifecycleMetadata(metadata)
	if len(sanitized.Mechanisms) > 0 {
		sanitized.Mechanisms = []EnforcementMechanism{EnforcementMechanismProxy}
	}
	sanitized.CapabilityLabels = sanitizeProxyListenerCapabilityLabels(sanitized.CapabilityLabels)
	return sanitized
}

func sanitizeProxyListenerCapabilityLabels(labels []string) []string {
	if len(labels) == 0 {
		return nil
	}
	sanitized := make([]string, 0, len(labels))
	for _, label := range labels {
		current := sanitizeIdentifier(label)
		if current == "" || current == "firewall" || current == "runtime" {
			continue
		}
		lower := normalizeEnum(current)
		if containsLifecycleLabelFragment(lower, "firewall") || containsLifecycleLabelFragment(lower, "runtime") {
			continue
		}
		sanitized = append(sanitized, current)
	}
	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
}

func containsLifecycleLabelFragment(value, fragment string) bool {
	if value == fragment {
		return true
	}
	return containsLifecycleSubstring(value, "_"+fragment) || containsLifecycleSubstring(value, fragment+"_")
}

func containsLifecycleSubstring(value, fragment string) bool {
	for i := 0; i+len(fragment) <= len(value); i++ {
		if value[i:i+len(fragment)] == fragment {
			return true
		}
	}
	return false
}

func appendLifecycleWarnings(existing []LifecycleWarningCode, values ...LifecycleWarningCode) []LifecycleWarningCode {
	if len(values) == 0 {
		return sanitizeLifecycleWarningCodeList(existing)
	}
	out := sanitizeLifecycleWarningCodeList(existing)
	for _, value := range values {
		current := sanitizeLifecycleWarningCode(value)
		if current == "" || lifecycleWarningCodeContains(out, current) {
			continue
		}
		out = append(out, current)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func lifecycleWarningCodeContains(values []LifecycleWarningCode, target LifecycleWarningCode) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
