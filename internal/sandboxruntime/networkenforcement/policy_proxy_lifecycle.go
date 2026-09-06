package networkenforcement

import "context"

const policyProxyCapabilityActive = "proxy_active"

// PolicyProxyLifecycleService is a concrete fake-testable policy proxy service
// backed by a ProxyListenerAdapter. It owns lifecycle proof translation while
// concrete listener work remains behind the injected adapter.
type PolicyProxyLifecycleService struct {
	Adapter ProxyListenerAdapter
}

var _ PolicyProxyService = PolicyProxyLifecycleService{}

// EvaluateConnectAuthority evaluates a CONNECT authority through the
// redaction-safe policy proxy decision contract.
func (s PolicyProxyLifecycleService) EvaluateConnectAuthority(_ context.Context, request PolicyProxyConnectAuthorityRequest) (PolicyProxyServiceDecisionResult, error) {
	return EvaluatePolicyProxyServiceDecisionResult(request.Policy, request.DecisionRequest()), nil
}

// EvaluateHTTPRequestHost evaluates an ordinary HTTP Host value through the
// redaction-safe policy proxy decision contract.
func (s PolicyProxyLifecycleService) EvaluateHTTPRequestHost(_ context.Context, request PolicyProxyHTTPRequestHostRequest) (PolicyProxyServiceDecisionResult, error) {
	return EvaluatePolicyProxyServiceDecisionResult(request.Policy, request.DecisionRequest()), nil
}

// StartPolicyProxy prepares and starts the proxy listener but does not claim
// active enforcement. Active enforcement requires a separate active check.
func (s PolicyProxyLifecycleService) StartPolicyProxy(ctx context.Context, request PolicyProxyLifecycleRequest) (PolicyProxyLifecycleProof, error) {
	request = SanitizePolicyProxyLifecycleRequest(request)
	plan := request.Plan.Plan()
	requested := requestedProxyListenerLifecycle(plan)

	if s.Adapter == nil {
		proof := failedPolicyProxyLifecycleProof(plan, ProxyListenerLifecycleMetadata{}, PolicyProxyLifecycleOperationStart, LifecycleReasonAdapterUnsupported, nil)
		return proof, policyProxyLifecycleError{operation: PolicyProxyLifecycleOperationStart, reason: LifecycleReasonAdapterUnsupported}
	}

	active := requested
	prepared, err := s.Adapter.PrepareProxyListener(ctx, ProxyListenerLifecycleRequest{
		Plan:      request.Plan,
		Requested: requested,
		Active:    active,
	})
	if err != nil {
		proof := failedPolicyProxyLifecycleProof(plan, prepared, PolicyProxyLifecycleOperationStart, LifecycleReasonAdapterFailed, nil)
		return proof, policyProxyLifecycleError{operation: PolicyProxyLifecycleOperationStart, reason: LifecycleReasonAdapterFailed}
	}
	active = completedProxyListenerLifecycleStep(plan, requested, prepared, proxyListenerOperationPrepare, LifecycleStatusPrepared, LifecycleReasonPrepared)

	started, err := s.Adapter.StartProxyListener(ctx, ProxyListenerLifecycleRequest{
		Plan:      request.Plan,
		Requested: requested,
		Active:    active,
	})
	if err != nil {
		warnings := s.stopAfterPolicyProxyStartFailure(ctx, request.Plan, requested, active)
		proof := failedPolicyProxyLifecycleProof(plan, started, PolicyProxyLifecycleOperationStart, LifecycleReasonAdapterFailed, warnings)
		return proof, policyProxyLifecycleError{operation: PolicyProxyLifecycleOperationStart, reason: LifecycleReasonAdapterFailed}
	}

	proof := policyProxyLifecycleProofFromListenerMetadata(plan, started, PolicyProxyLifecycleOperationStart, LifecycleStatusStarting, LifecycleReasonStarted)
	proof.Status = LifecycleStatusStarting
	proof.ReasonCode = LifecycleReasonStarted
	return finalizePolicyProxyLifecycleProof(proof), nil
}

// ActivePolicyProxy asks the adapter for active proxy proof. Non-active
// metadata, adapter errors, and warnings fail closed by clearing active claims.
func (s PolicyProxyLifecycleService) ActivePolicyProxy(ctx context.Context, request PolicyProxyLifecycleRequest) (PolicyProxyLifecycleProof, error) {
	request = SanitizePolicyProxyLifecycleRequest(request)
	plan := request.Plan.Plan()
	requested := requestedProxyListenerLifecycle(plan)
	active := policyProxyLifecycleProofToListenerMetadata(request.Active)
	if proxyListenerLifecycleMetadataEmpty(active) {
		active = policyProxyLifecycleProofToListenerMetadata(request.Requested)
	}
	if proxyListenerLifecycleMetadataEmpty(active) {
		active = requested
	}

	if s.Adapter == nil {
		proof := failedPolicyProxyLifecycleProof(plan, active, PolicyProxyLifecycleOperationActiveCheck, LifecycleReasonAdapterUnsupported, nil)
		return proof, policyProxyLifecycleError{operation: PolicyProxyLifecycleOperationActiveCheck, reason: LifecycleReasonAdapterUnsupported}
	}

	checked, err := s.Adapter.ActiveProxyListener(ctx, ProxyListenerLifecycleRequest{
		Plan:      request.Plan,
		Requested: requested,
		Active:    active,
	})
	if err != nil {
		proof := failedPolicyProxyLifecycleProof(plan, checked, PolicyProxyLifecycleOperationActiveCheck, LifecycleReasonActiveCheckFailed, nil)
		return proof, policyProxyLifecycleError{operation: PolicyProxyLifecycleOperationActiveCheck, reason: LifecycleReasonAdapterFailed, label: LifecycleReasonActiveCheckFailed}
	}

	proof := policyProxyLifecycleProofFromListenerMetadata(plan, checked, PolicyProxyLifecycleOperationActiveCheck, LifecycleStatusActive, LifecycleReasonActive)
	if sanitizeLifecycleStatus(checked.Status) != LifecycleStatusActive ||
		sanitizeLifecycleReasonCode(checked.ReasonCode) != LifecycleReasonActive ||
		!policyProxyLifecycleProofActive(proof) {
		proof = failedPolicyProxyLifecycleProof(plan, checked, PolicyProxyLifecycleOperationActiveCheck, LifecycleReasonActiveCheckFailed, []LifecycleWarningCode{LifecycleWarningActiveCheckFailed})
		return proof, policyProxyLifecycleError{operation: PolicyProxyLifecycleOperationActiveCheck, reason: LifecycleReasonActiveCheckFailed}
	}
	return finalizePolicyProxyLifecycleProof(proof), nil
}

// StopPolicyProxy stops a previously active proxy listener. Cleanup failures
// are returned as sanitized warnings and never preserve active enforcement.
func (s PolicyProxyLifecycleService) StopPolicyProxy(ctx context.Context, request PolicyProxyLifecycleRequest) (PolicyProxyLifecycleProof, error) {
	request = SanitizePolicyProxyLifecycleRequest(request)
	plan := request.Plan.Plan()
	requested := requestedProxyListenerLifecycle(plan)
	active := policyProxyLifecycleProofToListenerMetadata(request.Active)
	if proxyListenerLifecycleMetadataEmpty(active) {
		active = requested
	}

	if s.Adapter == nil {
		proof := policyProxyLifecycleProofFromListenerMetadata(plan, active, PolicyProxyLifecycleOperationStop, LifecycleStatusStopped, LifecycleReasonStopped)
		proof.WarningCodes = appendLifecycleWarnings(proof.WarningCodes, LifecycleWarningCleanupFailed, LifecycleWarningSanitizedAdapterError)
		return finalizePolicyProxyLifecycleProof(proof), nil
	}

	stopped, err := s.Adapter.StopProxyListener(ctx, ProxyListenerLifecycleRequest{
		Plan:      request.Plan,
		Requested: requested,
		Active:    active,
	})
	proof := policyProxyLifecycleProofFromListenerMetadata(plan, stopped, PolicyProxyLifecycleOperationStop, LifecycleStatusStopped, LifecycleReasonStopped)
	proof.Status = LifecycleStatusStopped
	proof.ReasonCode = LifecycleReasonStopped
	if err != nil {
		proof.WarningCodes = appendLifecycleWarnings(nil, LifecycleWarningCleanupFailed, LifecycleWarningSanitizedAdapterError)
	}
	return finalizePolicyProxyLifecycleProof(proof), nil
}

type policyProxyLifecycleError struct {
	operation PolicyProxyLifecycleOperation
	reason    LifecycleReasonCode
	label     LifecycleReasonCode
}

func (e policyProxyLifecycleError) Error() string {
	operation := sanitizePolicyProxyLifecycleOperation(e.operation)
	reason := sanitizeLifecycleReasonCode(e.reason)
	label := sanitizeLifecycleReasonCode(e.label)
	if operation == "" {
		operation = "policy_proxy"
	}
	if reason == "" {
		reason = LifecycleReasonAdapterFailed
	}
	message := "policy proxy lifecycle " + string(operation) + " " + string(reason)
	if label != "" && label != reason {
		message += " " + string(label)
	}
	return message
}

func (s PolicyProxyLifecycleService) stopAfterPolicyProxyStartFailure(ctx context.Context, plan SanitizedPlan, requested, active ProxyListenerLifecycleMetadata) []LifecycleWarningCode {
	if s.Adapter == nil {
		return []LifecycleWarningCode{LifecycleWarningCleanupFailed, LifecycleWarningSanitizedAdapterError}
	}
	_, err := s.Adapter.StopProxyListener(ctx, ProxyListenerLifecycleRequest{
		Plan:      plan,
		Requested: requested,
		Active:    active,
	})
	if err == nil {
		return nil
	}
	return []LifecycleWarningCode{LifecycleWarningCleanupFailed}
}

func policyProxyLifecycleProofFromListenerMetadata(plan Plan, metadata ProxyListenerLifecycleMetadata, operation PolicyProxyLifecycleOperation, status LifecycleStatus, reason LifecycleReasonCode) PolicyProxyLifecycleProof {
	metadata = sanitizeProxyListenerOnlyMetadata(metadata)
	proof := PolicyProxyLifecycleProof{
		PlanID:           metadata.PlanID,
		ProxySessionID:   metadata.ID,
		AdapterID:        metadata.AdapterID,
		Operation:        operation,
		Status:           metadata.Status,
		Mechanisms:       metadata.Mechanisms,
		Operations:       []PolicyProxyLifecycleOperation{operation},
		PolicySnapshot:   metadata.PolicySnapshot,
		CapabilityLabels: metadata.CapabilityLabels,
		ReasonCode:       metadata.ReasonCode,
		WarningCodes:     metadata.WarningCodes,
	}
	if proof.PlanID == "" {
		proof.PlanID = plan.ID
	}
	if proof.ProxySessionID == "" && plan.Proxy != nil {
		proof.ProxySessionID = plan.Proxy.ProxySessionID
	}
	if proof.Status == "" {
		proof.Status = status
	}
	if proof.PolicySnapshot == nil {
		proof.PolicySnapshot = sanitizePolicySnapshotIdentityPtr(plan.PolicySnapshot)
	}
	if proof.ReasonCode == "" {
		proof.ReasonCode = reason
	}
	return finalizePolicyProxyLifecycleProof(proof)
}

func policyProxyLifecycleProofToListenerMetadata(proof PolicyProxyLifecycleProof) ProxyListenerLifecycleMetadata {
	proof = SanitizePolicyProxyLifecycleProof(proof)
	metadata := ProxyListenerLifecycleMetadata{
		ID:               proof.ProxySessionID,
		PlanID:           proof.PlanID,
		AdapterID:        proof.AdapterID,
		Status:           proof.Status,
		Mechanisms:       proof.Mechanisms,
		Operations:       policyProxyLifecycleOperationsAsStrings(proof),
		PolicySnapshot:   proof.PolicySnapshot,
		CapabilityLabels: proof.CapabilityLabels,
		ReasonCode:       proof.ReasonCode,
		WarningCodes:     proof.WarningCodes,
	}
	return sanitizeProxyListenerOnlyMetadata(metadata)
}

func failedPolicyProxyLifecycleProof(plan Plan, metadata ProxyListenerLifecycleMetadata, operation PolicyProxyLifecycleOperation, reason LifecycleReasonCode, warnings []LifecycleWarningCode) PolicyProxyLifecycleProof {
	proof := policyProxyLifecycleProofFromListenerMetadata(plan, metadata, operation, LifecycleStatusFailed, reason)
	proof.Status = LifecycleStatusFailed
	proof.ReasonCode = reason
	proof.WarningCodes = appendLifecycleWarnings(proof.WarningCodes, LifecycleWarningSanitizedAdapterError)
	proof.WarningCodes = appendLifecycleWarnings(proof.WarningCodes, warnings...)
	return finalizePolicyProxyLifecycleProof(proof)
}

func finalizePolicyProxyLifecycleProof(proof PolicyProxyLifecycleProof) PolicyProxyLifecycleProof {
	proof = SanitizePolicyProxyLifecycleProof(proof)
	if policyProxyLifecycleProofActive(proof) {
		if len(proof.Mechanisms) == 0 {
			proof.Mechanisms = []EnforcementMechanism{EnforcementMechanismProxy}
		}
		proof.Mechanisms = sanitizePolicyProxyLifecycleMechanisms(proof.Mechanisms)
		proof.CapabilityLabels = appendPolicyProxyLifecycleCapabilityLabel(proof.CapabilityLabels, policyProxyCapabilityActive)
		return SanitizePolicyProxyLifecycleProof(proof)
	}
	proof.Mechanisms = nil
	proof.CapabilityLabels = nil
	return SanitizePolicyProxyLifecycleProof(proof)
}

func appendPolicyProxyLifecycleCapabilityLabel(values []string, label string) []string {
	sanitized := sanitizeProxyListenerCapabilityLabels(values)
	current := sanitizeIdentifier(label)
	if current == "" || stringSliceContains(sanitized, current) {
		return sanitized
	}
	return append(sanitized, current)
}

func stringSliceContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func policyProxyLifecycleProofActive(proof PolicyProxyLifecycleProof) bool {
	proof = SanitizePolicyProxyLifecycleProof(proof)
	return proof.Status == LifecycleStatusActive &&
		proof.ReasonCode == LifecycleReasonActive &&
		len(proof.WarningCodes) == 0
}

func policyProxyLifecycleOperationsAsStrings(proof PolicyProxyLifecycleProof) []string {
	operations := make([]string, 0, len(proof.Operations)+1)
	for _, operation := range proof.Operations {
		if current := sanitizePolicyProxyLifecycleOperation(operation); current != "" {
			operations = append(operations, string(current))
		}
	}
	if len(operations) == 0 {
		if operation := sanitizePolicyProxyLifecycleOperation(proof.Operation); operation != "" {
			operations = append(operations, string(operation))
		}
	}
	return sanitizeIdentifierList(operations)
}
