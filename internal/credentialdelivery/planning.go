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
	NetworkEnforcementProof *sandbox.SandboxNetworkEnforcementProofMetadata
	CredentialProxyPlan     *sandbox.SandboxCredentialProxyPlanMetadata
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
	hasExplicitRequestedModes := len(request.RequestedModes) > 0
	bindings := validatedPlanBindings(&plan, requestedModes, request.Bindings)
	if !hasExplicitRequestedModes {
		addSecureDefaultPlanModesForServiceDomainBindings(requestedModes, bindings)
	}
	resolvedByBindingID := resolvedPlanBindingsByID(request.ResolvedBindings)
	proxyContext := newPlanProxyContext(request)

	plan.BindingCount = countPlanBindingsWithBrokerMetadata(bindings, resolvedByBindingID)
	plan.RequestedModes = requestedModes.ordered()
	if len(plan.Errors) > 0 {
		plan.Status = StatusFailed
		return SanitizePlanMetadata(plan)
	}
	if requestedModes.contains(ModeHTTPProxy) {
		if proof := activeHTTPProxyPlanProof(bindings, resolvedByBindingID, proxyContext); proof != nil {
			plan.HTTPProxyProof = proof
			plan.NetworkProxySessionID = proof.NetworkEnforcement.NetworkProxySessionID
		}
	}
	if plan.NetworkProxySessionID != "" {
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

func activeHTTPProxyPlanProof(bindings []Binding, resolvedByBindingID map[string]ResolvedBindingSecretMetadata, proxyContext planProxyContext) *HTTPProxyProof {
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
		if proof := proxyContext.httpProxyActivationProof(binding, resolved); proof != nil {
			return proof
		}
	}
	return nil
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
		case ModeSSHAgent, ModeFileTmpfs:
			plan.Warnings = append(plan.Warnings, Warning{
				Code:       WarningAdapterUnavailable,
				ReasonCode: ReasonActivationUnavailable,
				Mode:       mode,
			})
		case ModeEnv:
			plan.Warnings = append(plan.Warnings, Warning{
				Code:       WarningCompatibilityMode,
				ReasonCode: ReasonCompatibilityMode,
				Mode:       ModeEnv,
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

func addSecureDefaultPlanModesForServiceDomainBindings(modes *planModeSet, bindings []Binding) {
	for _, binding := range bindings {
		if !bindingHasSafeServiceDomainMetadata(binding) {
			continue
		}
		modes.add(ModeHTTPProxy)
		modes.add(ModeSSHAgent)
		modes.add(ModeFileTmpfs)
		return
	}
}

func bindingHasSafeServiceDomainMetadata(binding Binding) bool {
	binding = SanitizeBindingMetadata(binding)
	if binding.ID == "" {
		return false
	}
	if binding.ServiceID != "" || len(binding.ServiceLabels) > 0 || len(binding.DomainLabels) > 0 {
		return true
	}
	switch binding.DestinationCategory {
	case DestinationPublicInternet,
		DestinationPrivateNetwork,
		DestinationMetadataService,
		DestinationLoopback,
		DestinationUnixSocket:
		return true
	default:
		return false
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
	networkProxySessionID    string
	networkEnforcementProof  sandbox.SandboxNetworkEnforcementProofMetadata
	credentialProxyPlanID    string
	credentialProxyPlanReady bool
	credentialProxySessionID string
	secretBrokerSessionID    string
	credentialProxyNetworkID string
	policySnapshotIDs        map[string]struct{}
	credentialProxyBindings  map[string]sandbox.SandboxCredentialProxyBindingMetadata
}

func newPlanProxyContext(request PlanConstructionRequest) planProxyContext {
	context := planProxyContext{
		policySnapshotIDs:       make(map[string]struct{}),
		credentialProxyBindings: make(map[string]sandbox.SandboxCredentialProxyBindingMetadata),
	}
	context.addPolicySnapshot(request.PolicySnapshot)
	if request.NetworkProxySession != nil {
		session := sandbox.SanitizeSandboxNetworkProxySessionMetadata(*request.NetworkProxySession)
		if session.ID != "" {
			context.networkProxySessionID = session.ID
		}
		context.addPolicySnapshot(session.PolicySnapshot)
	}
	if request.NetworkEnforcementProof != nil {
		context.networkEnforcementProof = sandbox.SanitizeSandboxNetworkEnforcementProofMetadata(*request.NetworkEnforcementProof)
	}
	if request.CredentialProxyPlan != nil {
		plan := sandbox.SanitizeSandboxCredentialProxyPlanMetadata(*request.CredentialProxyPlan)
		if plan.ID != "" {
			context.credentialProxyPlanID = plan.ID
			context.credentialProxyPlanReady = usableCredentialProxyStatus(plan.Status) &&
				plan.Mode == sandbox.SandboxCredentialProxyModeBrokeredNetworkReference
			context.secretBrokerSessionID = plan.SecretBrokerSessionID
			context.credentialProxyNetworkID = plan.NetworkProxySessionID
			context.addPolicySnapshot(plan.PolicySnapshot)
		}
	}
	if request.CredentialProxySession != nil {
		session := sandbox.SanitizeSandboxCredentialProxySessionMetadata(*request.CredentialProxySession)
		if session.ID != "" && context.credentialProxySessionCorrelates(session) {
			context.credentialProxySessionID = session.ID
			context.secretBrokerSessionID = session.SecretBrokerSessionID
			context.credentialProxyNetworkID = session.NetworkProxySessionID
			context.addPolicySnapshot(session.PolicySnapshot)
		}
	}
	context.addCredentialProxyBindings(request.CredentialProxyBindings)
	if len(context.policySnapshotIDs) == 0 {
		context.policySnapshotIDs = nil
	}
	if len(context.credentialProxyBindings) == 0 {
		context.credentialProxyBindings = nil
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
			!c.credentialProxyBindingPlanSessionMatches(binding) ||
			!usableCredentialProxyBinding(binding) {
			continue
		}
		c.credentialProxyBindings[binding.SecretID] = binding
	}
}

func (c planProxyContext) credentialProxySessionCorrelates(session sandbox.SandboxCredentialProxySessionMetadata) bool {
	if !c.credentialProxyPlanReady ||
		c.credentialProxyPlanID == "" ||
		session.PlanID != c.credentialProxyPlanID ||
		session.SecretBrokerSessionID == "" ||
		session.NetworkProxySessionID == "" ||
		!usableCredentialProxyStatus(session.Status) {
		return false
	}
	if c.secretBrokerSessionID != "" && session.SecretBrokerSessionID != c.secretBrokerSessionID {
		return false
	}
	if c.credentialProxyNetworkID != "" && session.NetworkProxySessionID != c.credentialProxyNetworkID {
		return false
	}
	return true
}

func (c planProxyContext) credentialProxyBindingPlanSessionMatches(binding sandbox.SandboxCredentialProxyBindingMetadata) bool {
	if !c.credentialProxyPlanReady || c.credentialProxyPlanID == "" || c.credentialProxySessionID == "" {
		return false
	}
	return binding.PlanID == c.credentialProxyPlanID && binding.SessionID == c.credentialProxySessionID
}

func usableCredentialProxyBinding(binding sandbox.SandboxCredentialProxyBindingMetadata) bool {
	if binding.Outcome != sandbox.SandboxCredentialProxyBindingOutcomeBound {
		return false
	}
	return usableCredentialProxyStatus(binding.Status)
}

func usableCredentialProxyStatus(status sandbox.SandboxCredentialProxyStatus) bool {
	switch status {
	case sandbox.SandboxCredentialProxyStatusReady,
		sandbox.SandboxCredentialProxyStatusActive,
		sandbox.SandboxCredentialProxyStatusCompleted:
		return true
	default:
		return false
	}
}

func (c planProxyContext) policyAllows(bindingPolicySnapshotID string) bool {
	if bindingPolicySnapshotID == "" || len(c.policySnapshotIDs) == 0 {
		return true
	}
	_, ok := c.policySnapshotIDs[bindingPolicySnapshotID]
	return ok
}

func (c planProxyContext) networkProxySessionForBinding(bindingNetworkProxySessionID string) string {
	if bindingNetworkProxySessionID == "" {
		return ""
	}
	if bindingNetworkProxySessionID == c.networkProxySessionID ||
		bindingNetworkProxySessionID == c.credentialProxyNetworkID {
		return bindingNetworkProxySessionID
	}
	return ""
}

func (c planProxyContext) defaultNetworkProxySessionID() string {
	if c.credentialProxyNetworkID != "" {
		return c.credentialProxyNetworkID
	}
	return c.networkProxySessionID
}

func (c planProxyContext) httpProxyActivationProof(binding Binding, resolved ResolvedBindingSecretMetadata) *HTTPProxyProof {
	credentialBinding, ok := c.credentialProxyBindings[resolved.BrokerSecret.ID]
	if !ok || c.secretBrokerSessionID == "" {
		return nil
	}
	networkSessionID := c.networkProxySessionForBinding(binding.NetworkProxySessionID)
	if networkSessionID == "" && credentialBinding.SessionID == c.credentialProxySessionID {
		networkSessionID = c.defaultNetworkProxySessionID()
	}
	if networkSessionID == "" ||
		c.networkEnforcementProof.NetworkProxySessionID != networkSessionID ||
		c.networkEnforcementProof.PolicySnapshotID == "" ||
		!sandbox.SandboxNetworkEnforcementProofProvesActiveHTTPProxy(c.networkEnforcementProof) {
		return nil
	}
	if binding.PolicySnapshotID == "" || c.networkEnforcementProof.PolicySnapshotID != binding.PolicySnapshotID {
		return nil
	}
	if credentialBinding.SecretID != resolved.BrokerSecret.ID {
		return nil
	}
	proof := SanitizeHTTPProxyProofMetadata(HTTPProxyProof{
		BindingID:                binding.ID,
		SecretID:                 resolved.BrokerSecret.ID,
		SecretBrokerSessionID:    c.secretBrokerSessionID,
		CredentialProxyPlanID:    c.credentialProxyPlanID,
		CredentialProxySessionID: c.credentialProxySessionID,
		CredentialProxyBindingID: credentialBinding.ID,
		NetworkEnforcement:       &c.networkEnforcementProof,
	})
	if proof.BindingID == "" || proof.NetworkEnforcement == nil {
		return nil
	}
	return &proof
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
