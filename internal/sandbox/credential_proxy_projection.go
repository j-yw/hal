package sandbox

import "strconv"

// SandboxCredentialProxyProjectionRequest contains the already-safe metadata
// inputs needed to project credential proxy records for durable persistence.
type SandboxCredentialProxyProjectionRequest struct {
	PlanID                string
	SessionID             string
	BindingIDPrefix       string
	Source                SandboxCredentialProxySource
	SecretBrokerSessionID string
	SecretIDs             []string
	SecretDeliveryIntent  *SandboxSecretDeliveryIntent
	NetworkProxySession   *SandboxNetworkProxySessionMetadata
	RequestCategory       SandboxCredentialProxyRequestCategory
	DestinationCategory   SandboxNetworkPolicyDestinationCategory
}

// SandboxCredentialProxyProjection is the exact credential proxy metadata
// surface persisted by command and factory sandbox records.
type SandboxCredentialProxyProjection struct {
	Plan     *SandboxCredentialProxyPlanMetadata
	Session  *SandboxCredentialProxySessionMetadata
	Bindings []SandboxCredentialProxyBindingMetadata
}

type sandboxCredentialProxyProjectedMode struct {
	mode      SandboxCredentialProxyDeliveryMode
	requested bool
	active    bool
}

// ProjectSandboxCredentialProxyMetadata derives credential proxy plan, session,
// and binding metadata using only redaction-safe IDs and enum-like labels.
func ProjectSandboxCredentialProxyMetadata(request SandboxCredentialProxyProjectionRequest) SandboxCredentialProxyProjection {
	secretBrokerSessionID := sanitizeSandboxCredentialProxyIdentifier(NormalizeSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
		SecretBrokerSessionID: request.SecretBrokerSessionID,
	}).SecretBrokerSessionID)
	networkProxySession := sanitizeSandboxCredentialProxyProjectionNetworkSession(request.NetworkProxySession)
	mode := sandboxCredentialProxyProjectionMode(secretBrokerSessionID, networkProxySession.ID)
	if mode == "" {
		return SandboxCredentialProxyProjection{}
	}

	plan := SanitizeSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
		ID:                    request.PlanID,
		Source:                request.Source,
		SecretBrokerSessionID: secretBrokerSessionID,
		NetworkProxySessionID: networkProxySession.ID,
		PolicySnapshot:        networkProxySession.PolicySnapshot,
		Mode:                  mode,
		Status:                SandboxCredentialProxyStatusPlanned,
	})
	if plan.ID == "" || plan.Source == "" {
		return SandboxCredentialProxyProjection{}
	}

	session := SanitizeSandboxCredentialProxySessionMetadata(SandboxCredentialProxySessionMetadata{
		ID:                    request.SessionID,
		PlanID:                plan.ID,
		Source:                request.Source,
		SecretBrokerSessionID: secretBrokerSessionID,
		NetworkProxySessionID: networkProxySession.ID,
		PolicySnapshot:        networkProxySession.PolicySnapshot,
		Status:                SandboxCredentialProxyStatusReady,
	})
	if session.ID == "" {
		return SandboxCredentialProxyProjection{}
	}

	secretIDs := sanitizeSandboxCredentialProxyProjectionSecretIDs(request.SecretIDs)
	projectedModes, unsupportedMode := sandboxCredentialProxyProjectionDeliveryModes(request.SecretDeliveryIntent)
	bindings := projectSandboxCredentialProxyBindings(projectSandboxCredentialProxyBindingsRequest{
		PlanID:              plan.ID,
		SessionID:           session.ID,
		BindingIDPrefix:     request.BindingIDPrefix,
		SecretIDs:           secretIDs,
		Modes:               projectedModes,
		RequestCategory:     request.RequestCategory,
		DestinationCategory: request.DestinationCategory,
	})
	plan.BindingCount = len(bindings)
	if len(bindings) == 0 {
		session = sandboxCredentialProxyProjectionSessionWithOmission(session, request, unsupportedMode)
	}

	return SandboxCredentialProxyProjection{
		Plan:     &plan,
		Session:  &session,
		Bindings: sandboxCredentialProxyProjectionBindingsResult(bindings, request),
	}
}

func sanitizeSandboxCredentialProxyProjectionNetworkSession(session *SandboxNetworkProxySessionMetadata) SandboxNetworkProxySessionMetadata {
	if session == nil {
		return SandboxNetworkProxySessionMetadata{}
	}
	sanitized := SanitizeSandboxNetworkProxySessionMetadata(*session)
	if sanitized.ID == "" {
		return SandboxNetworkProxySessionMetadata{}
	}
	return sanitized
}

func sandboxCredentialProxyProjectionMode(secretBrokerSessionID, networkProxySessionID string) SandboxCredentialProxyMode {
	switch {
	case secretBrokerSessionID != "" && networkProxySessionID != "":
		return SandboxCredentialProxyModeBrokeredNetworkReference
	case secretBrokerSessionID != "":
		return SandboxCredentialProxyModeSecretBrokerReference
	case networkProxySessionID != "":
		return SandboxCredentialProxyModeNetworkProxyReference
	default:
		return ""
	}
}

func sanitizeSandboxCredentialProxyProjectionSecretIDs(secretIDs []string) []string {
	if secretIDs == nil {
		return nil
	}
	out := make([]string, 0, len(secretIDs))
	for _, secretID := range secretIDs {
		sanitized := sanitizeSandboxCredentialProxySecretReference(NormalizeSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
			SecretID: secretID,
		}).SecretID)
		if sanitized == "" {
			continue
		}
		if !sandboxCredentialProxyProjectionContainsSecretID(out, sanitized) {
			out = append(out, sanitized)
		}
	}
	return out
}

func sandboxCredentialProxyProjectionDeliveryModes(intent *SandboxSecretDeliveryIntent) ([]sandboxCredentialProxyProjectedMode, bool) {
	if intent == nil {
		return nil, false
	}
	modes := make([]sandboxCredentialProxyProjectedMode, 0, len(intent.RequestedModes)+len(intent.ActiveModes))
	unsupported := false
	for _, mode := range intent.RequestedModes {
		projected, ok := sandboxCredentialProxyProjectionDeliveryMode(mode)
		if !ok {
			unsupported = true
			continue
		}
		index := sandboxCredentialProxyProjectionModeIndex(modes, projected)
		if index < 0 {
			modes = append(modes, sandboxCredentialProxyProjectedMode{mode: projected, requested: true})
			continue
		}
		modes[index].requested = true
	}
	for _, mode := range intent.ActiveModes {
		projected, ok := sandboxCredentialProxyProjectionDeliveryMode(mode)
		if !ok {
			unsupported = true
			continue
		}
		index := sandboxCredentialProxyProjectionModeIndex(modes, projected)
		if index < 0 {
			modes = append(modes, sandboxCredentialProxyProjectedMode{mode: projected, active: true})
			continue
		}
		modes[index].active = true
	}
	return modes, unsupported
}

func sandboxCredentialProxyProjectionDeliveryMode(mode string) (SandboxCredentialProxyDeliveryMode, bool) {
	projected := normalizeSandboxCredentialProxyDeliveryMode(SandboxCredentialProxyDeliveryMode(mode))
	if !validSandboxCredentialProxyDeliveryMode(string(projected)) {
		return "", false
	}
	return projected, true
}

func sandboxCredentialProxyProjectionModeIndex(modes []sandboxCredentialProxyProjectedMode, mode SandboxCredentialProxyDeliveryMode) int {
	for i, existing := range modes {
		if existing.mode == mode {
			return i
		}
	}
	return -1
}

type projectSandboxCredentialProxyBindingsRequest struct {
	PlanID              string
	SessionID           string
	BindingIDPrefix     string
	SecretIDs           []string
	Modes               []sandboxCredentialProxyProjectedMode
	RequestCategory     SandboxCredentialProxyRequestCategory
	DestinationCategory SandboxNetworkPolicyDestinationCategory
}

func projectSandboxCredentialProxyBindings(request projectSandboxCredentialProxyBindingsRequest) []SandboxCredentialProxyBindingMetadata {
	if len(request.SecretIDs) == 0 || len(request.Modes) == 0 {
		return nil
	}
	bindings := make([]SandboxCredentialProxyBindingMetadata, 0, len(request.SecretIDs)*len(request.Modes))
	for _, secretID := range request.SecretIDs {
		for _, mode := range request.Modes {
			binding := SanitizeSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
				ID:                  sandboxCredentialProxyProjectionBindingID(request.BindingIDPrefix, request.SessionID, len(bindings)),
				PlanID:              request.PlanID,
				SessionID:           request.SessionID,
				SecretID:            secretID,
				DeliveryMode:        mode.mode,
				RequestCategory:     request.RequestCategory,
				DestinationCategory: request.DestinationCategory,
				Outcome:             sandboxCredentialProxyProjectionBindingOutcome(mode),
				Status:              sandboxCredentialProxyProjectionBindingStatus(mode),
				ReasonCode:          SandboxCredentialProxyReasonRequested,
			})
			if binding.ID == "" {
				continue
			}
			bindings = append(bindings, binding)
		}
	}
	if len(bindings) == 0 {
		return nil
	}
	return bindings
}

func sandboxCredentialProxyProjectionBindingID(prefix, sessionID string, index int) string {
	base := sanitizeSandboxCredentialProxyIdentifier(NormalizeSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
		ID: prefix,
	}).ID)
	if base == "" {
		base = sanitizeSandboxCredentialProxyIdentifier(sessionID)
	}
	if base == "" {
		base = "credential-binding"
	}
	return base + "-binding-" + strconv.Itoa(index+1)
}

func sandboxCredentialProxyProjectionBindingOutcome(mode sandboxCredentialProxyProjectedMode) SandboxCredentialProxyBindingOutcome {
	if mode.active {
		return SandboxCredentialProxyBindingOutcomeAuditOnly
	}
	return SandboxCredentialProxyBindingOutcomePlanned
}

func sandboxCredentialProxyProjectionBindingStatus(mode sandboxCredentialProxyProjectedMode) SandboxCredentialProxyStatus {
	if mode.active {
		return SandboxCredentialProxyStatusReady
	}
	return SandboxCredentialProxyStatusPlanned
}

func sandboxCredentialProxyProjectionSessionWithOmission(session SandboxCredentialProxySessionMetadata, request SandboxCredentialProxyProjectionRequest, unsupportedMode bool) SandboxCredentialProxySessionMetadata {
	if unsupportedMode {
		session.WarningCode = SandboxCredentialProxyWarningUnsupportedDeliveryMode
		session.ReasonCode = SandboxCredentialProxyReasonDeliveryModeUnsupported
		return SanitizeSandboxCredentialProxySessionMetadata(session)
	}
	if sandboxCredentialProxyProjectionBindingInputsExplicit(request) {
		session.WarningCode = SandboxCredentialProxyWarningBindingOmitted
		session.ReasonCode = SandboxCredentialProxyReasonRequested
		return SanitizeSandboxCredentialProxySessionMetadata(session)
	}
	return session
}

func sandboxCredentialProxyProjectionBindingsResult(bindings []SandboxCredentialProxyBindingMetadata, request SandboxCredentialProxyProjectionRequest) []SandboxCredentialProxyBindingMetadata {
	if len(bindings) > 0 {
		return append([]SandboxCredentialProxyBindingMetadata(nil), bindings...)
	}
	if sandboxCredentialProxyProjectionBindingInputsExplicit(request) {
		return []SandboxCredentialProxyBindingMetadata{}
	}
	return nil
}

func sandboxCredentialProxyProjectionBindingInputsExplicit(request SandboxCredentialProxyProjectionRequest) bool {
	if request.SecretIDs != nil {
		return true
	}
	if request.SecretDeliveryIntent == nil {
		return false
	}
	return request.SecretDeliveryIntent.RequestedModes != nil || request.SecretDeliveryIntent.ActiveModes != nil
}

func sandboxCredentialProxyProjectionContainsSecretID(secretIDs []string, secretID string) bool {
	for _, existing := range secretIDs {
		if existing == secretID {
			return true
		}
	}
	return false
}
