package credentialdelivery

import "github.com/jywlabs/hal/internal/sandbox"

// PlanConstructionRequest contains only previously validated credential
// delivery metadata and optional safe proxy/policy references.
type PlanConstructionRequest struct {
	PlanID                  string
	RequestID               string
	Bindings                []Binding
	RequestedModes          []Mode
	ResolvedBindings        []ResolvedBindingSecretMetadata
	PolicySnapshot          *sandbox.SandboxNetworkPolicySnapshotIdentity
	NetworkProxySession     *sandbox.SandboxNetworkProxySessionMetadata
	CredentialProxySession  *sandbox.SandboxCredentialProxySessionMetadata
	CredentialProxyBindings []sandbox.SandboxCredentialProxyBindingMetadata
}

// BuildDeliveryPlan constructs a deterministic delivery plan summary from
// validated binding metadata without invoking any runtime delivery adapter.
func BuildDeliveryPlan(request PlanConstructionRequest) Plan {
	plan := Plan{
		ID:        request.PlanID,
		RequestID: request.RequestID,
		Status:    StatusPlanned,
	}
	requestedModes := newPlanModeSet()

	addRequestedPlanModes(&plan, requestedModes, request.RequestedModes)
	bindings := validatedPlanBindings(&plan, requestedModes, request.Bindings)
	resolvedByBindingID := resolvedPlanBindingsByID(request.ResolvedBindings)
	proxyContext := newPlanProxyContext(request)

	plan.BindingCount = countPlanBindingsWithBrokerMetadata(bindings, resolvedByBindingID)
	plan.RequestedModes = requestedModes.ordered()
	if len(plan.Errors) > 0 {
		plan.Status = StatusFailed
		return SanitizePlanMetadata(plan)
	}
	if requestedModes.contains(ModeHTTPProxy) && hasActiveHTTPProxyPlanBinding(bindings, resolvedByBindingID, proxyContext) {
		plan.ActiveModes = []Mode{ModeHTTPProxy}
	}
	addPlanModeWarnings(&plan, requestedModes, len(plan.ActiveModes) > 0)
	return SanitizePlanMetadata(plan)
}

func addRequestedPlanModes(plan *Plan, modes *planModeSet, requested []Mode) {
	for i, mode := range normalizeModeRecords(requested) {
		if mode == "" {
			plan.addPlanError(ErrorMissingRequiredField, "requestedModes", "", "", &i, ReasonUnsupportedMode)
			continue
		}
		if !validMode(mode) {
			plan.addPlanError(ErrorUnsupportedMode, "requestedModes", "", mode, &i, ReasonUnsupportedMode)
			continue
		}
		modes.add(mode)
	}
}

func validatedPlanBindings(plan *Plan, modes *planModeSet, bindings []Binding) []Binding {
	if len(bindings) == 0 {
		return nil
	}
	out := make([]Binding, 0, len(bindings))
	for i, binding := range NormalizeBindingMetadataRecords(bindings) {
		validation := ValidateBindingMetadata(binding)
		if !validation.Valid {
			for _, err := range validation.Errors {
				plan.addPlanError(err.Code, planBindingField(err.Field), binding.ID, err.Mode, &i, err.ReasonCode)
			}
			continue
		}
		sanitized := SanitizeBindingMetadata(binding)
		if sanitized.ID == "" {
			continue
		}
		modes.add(sanitized.DeliveryMode)
		out = append(out, sanitized)
	}
	return out
}

func resolvedPlanBindingsByID(bindings []ResolvedBindingSecretMetadata) map[string]ResolvedBindingSecretMetadata {
	resolved := SanitizeResolvedBindingSecretMetadataRecords(bindings)
	if len(resolved) == 0 {
		return nil
	}
	out := make(map[string]ResolvedBindingSecretMetadata, len(resolved))
	for _, binding := range resolved {
		if binding.BrokerSecret.Present {
			out[binding.BindingID] = binding
		}
	}
	return out
}

func countPlanBindingsWithBrokerMetadata(bindings []Binding, resolvedByBindingID map[string]ResolvedBindingSecretMetadata) int {
	count := 0
	for _, binding := range bindings {
		if resolvedPlanBindingMatches(binding, resolvedByBindingID[binding.ID]) {
			count++
		}
	}
	return count
}

func hasActiveHTTPProxyPlanBinding(bindings []Binding, resolvedByBindingID map[string]ResolvedBindingSecretMetadata, proxyContext planProxyContext) bool {
	for _, binding := range bindings {
		if binding.DeliveryMode != ModeHTTPProxy {
			continue
		}
		resolved := resolvedByBindingID[binding.ID]
		if !resolvedPlanBindingMatches(binding, resolved) {
			continue
		}
		if !proxyContext.policyAllows(binding.PolicySnapshotID) {
			continue
		}
		if proxyContext.hasNetworkProxySession(binding.NetworkProxySessionID) {
			return true
		}
		if proxyContext.hasCredentialProxyBinding(resolved.BrokerSecret.ID) {
			return true
		}
	}
	return false
}

func resolvedPlanBindingMatches(binding Binding, resolved ResolvedBindingSecretMetadata) bool {
	return resolved.BindingID == binding.ID &&
		resolved.SecretRef == binding.SecretRef &&
		resolved.BrokerSecret.ID == binding.SecretRef &&
		resolved.BrokerSecret.Present
}

func addPlanModeWarnings(plan *Plan, requestedModes *planModeSet, httpProxyActive bool) {
	for _, mode := range requestedModes.ordered() {
		switch mode {
		case ModeHTTPProxy:
			if !httpProxyActive {
				plan.Warnings = append(plan.Warnings, Warning{
					Code:       WarningActivationSkipped,
					ReasonCode: ReasonMissingServiceBinding,
					Mode:       ModeHTTPProxy,
				})
			}
		case ModeSSHAgent, ModeFileTmpfs, ModeEnv:
			plan.Warnings = append(plan.Warnings, Warning{
				Code:       WarningAdapterUnavailable,
				ReasonCode: ReasonActivationUnavailable,
				Mode:       mode,
			})
		case ModeLegacyAuthSync:
			plan.Warnings = append(plan.Warnings, Warning{
				Code:       WarningLegacyAuthCompatibility,
				ReasonCode: ReasonCompatibilityMode,
				Mode:       ModeLegacyAuthSync,
			})
		}
	}
}

func planBindingField(field string) string {
	if field == "" {
		return "bindings"
	}
	return "bindings." + field
}

func (p *Plan) addPlanError(code ErrorCode, field, bindingID string, mode Mode, index *int, reason ReasonCode) {
	err := SanitizedError{
		Code:       code,
		Field:      field,
		BindingID:  bindingID,
		Mode:       mode,
		ReasonCode: reason,
	}
	if index != nil {
		idx := *index
		err.Index = &idx
	}
	p.Errors = append(p.Errors, err)
}

type planProxyContext struct {
	networkProxySessionID     string
	credentialProxySessionID  string
	credentialProxyNetworkID  string
	policySnapshotIDs         map[string]struct{}
	credentialProxySecretRefs map[string]struct{}
}

func newPlanProxyContext(request PlanConstructionRequest) planProxyContext {
	context := planProxyContext{
		policySnapshotIDs:         make(map[string]struct{}),
		credentialProxySecretRefs: make(map[string]struct{}),
	}
	context.addPolicySnapshot(request.PolicySnapshot)
	if request.NetworkProxySession != nil {
		session := sandbox.SanitizeSandboxNetworkProxySessionMetadata(*request.NetworkProxySession)
		if session.ID != "" {
			context.networkProxySessionID = session.ID
		}
		context.addPolicySnapshot(session.PolicySnapshot)
	}
	if request.CredentialProxySession != nil {
		session := sandbox.SanitizeSandboxCredentialProxySessionMetadata(*request.CredentialProxySession)
		if session.ID != "" {
			context.credentialProxySessionID = session.ID
			context.credentialProxyNetworkID = session.NetworkProxySessionID
			context.addPolicySnapshot(session.PolicySnapshot)
		}
	}
	context.addCredentialProxyBindings(request.CredentialProxyBindings)
	if len(context.policySnapshotIDs) == 0 {
		context.policySnapshotIDs = nil
	}
	if len(context.credentialProxySecretRefs) == 0 {
		context.credentialProxySecretRefs = nil
	}
	return context
}

func (c *planProxyContext) addPolicySnapshot(snapshot *sandbox.SandboxNetworkPolicySnapshotIdentity) {
	if snapshot == nil {
		return
	}
	sanitized := sandbox.SanitizeSandboxCredentialProxyPlanMetadata(sandbox.SandboxCredentialProxyPlanMetadata{
		ID:             "credential-delivery-plan-policy",
		Source:         sandbox.SandboxCredentialProxySourceRun,
		PolicySnapshot: snapshot,
	}).PolicySnapshot
	if sanitized != nil && sanitized.ID != "" {
		c.policySnapshotIDs[sanitized.ID] = struct{}{}
	}
}

func (c *planProxyContext) addCredentialProxyBindings(bindings []sandbox.SandboxCredentialProxyBindingMetadata) {
	for _, raw := range bindings {
		binding := sandbox.SanitizeSandboxCredentialProxyBindingMetadata(raw)
		if binding.ID == "" ||
			binding.DeliveryMode != sandbox.SandboxCredentialProxyDeliveryModeHTTPProxy ||
			!c.credentialProxyBindingSessionMatches(binding) ||
			!usableCredentialProxyBinding(binding) {
			continue
		}
		c.credentialProxySecretRefs[binding.SecretID] = struct{}{}
	}
}

func (c planProxyContext) credentialProxyBindingSessionMatches(binding sandbox.SandboxCredentialProxyBindingMetadata) bool {
	if c.credentialProxySessionID != "" {
		return binding.SessionID == "" || binding.SessionID == c.credentialProxySessionID
	}
	return c.networkProxySessionID != "" || c.credentialProxyNetworkID != ""
}

func usableCredentialProxyBinding(binding sandbox.SandboxCredentialProxyBindingMetadata) bool {
	switch binding.Outcome {
	case sandbox.SandboxCredentialProxyBindingOutcomeOmitted,
		sandbox.SandboxCredentialProxyBindingOutcomeSkipped,
		sandbox.SandboxCredentialProxyBindingOutcomeFailed:
		return false
	}
	switch binding.Status {
	case sandbox.SandboxCredentialProxyStatusDisabled,
		sandbox.SandboxCredentialProxyStatusSkipped,
		sandbox.SandboxCredentialProxyStatusFailed:
		return false
	}
	return true
}

func (c planProxyContext) policyAllows(bindingPolicySnapshotID string) bool {
	if bindingPolicySnapshotID == "" || len(c.policySnapshotIDs) == 0 {
		return true
	}
	_, ok := c.policySnapshotIDs[bindingPolicySnapshotID]
	return ok
}

func (c planProxyContext) hasNetworkProxySession(bindingNetworkProxySessionID string) bool {
	if bindingNetworkProxySessionID == "" {
		return false
	}
	return bindingNetworkProxySessionID == c.networkProxySessionID ||
		bindingNetworkProxySessionID == c.credentialProxyNetworkID
}

func (c planProxyContext) hasCredentialProxyBinding(secretRef string) bool {
	if len(c.credentialProxySecretRefs) == 0 {
		return false
	}
	if c.networkProxySessionID == "" && c.credentialProxyNetworkID == "" {
		return false
	}
	_, ok := c.credentialProxySecretRefs[secretRef]
	return ok
}

type planModeSet struct {
	values map[Mode]struct{}
}

func newPlanModeSet() *planModeSet {
	return &planModeSet{values: make(map[Mode]struct{})}
}

func (s *planModeSet) add(mode Mode) {
	mode = normalizeMode(mode)
	if mode == "" || !validMode(mode) {
		return
	}
	s.values[mode] = struct{}{}
}

func (s *planModeSet) contains(mode Mode) bool {
	_, ok := s.values[mode]
	return ok
}

func (s *planModeSet) ordered() []Mode {
	if len(s.values) == 0 {
		return nil
	}
	out := make([]Mode, 0, len(s.values))
	for _, mode := range SupportedModes() {
		if s.contains(mode) {
			out = append(out, mode)
		}
	}
	return out
}
