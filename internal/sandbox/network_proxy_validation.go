package sandbox

import "strings"

// SandboxNetworkProxyValidationCode identifies a sanitized proxy metadata
// validation failure. Codes must not include raw request, destination, or
// credential values.
type SandboxNetworkProxyValidationCode string

const (
	SandboxNetworkProxyValidationMissingRequiredField SandboxNetworkProxyValidationCode = "missing_required_field"
	SandboxNetworkProxyValidationInvalidSource        SandboxNetworkProxyValidationCode = "invalid_source"
	SandboxNetworkProxyValidationInvalidPolicyPreset  SandboxNetworkProxyValidationCode = "invalid_policy_preset"
	SandboxNetworkProxyValidationInvalidEnforcement   SandboxNetworkProxyValidationCode = "invalid_enforcement_mode"
)

// SandboxNetworkProxyValidationError identifies invalid proxy metadata by safe
// field name only. It intentionally omits rejected input values.
type SandboxNetworkProxyValidationError struct {
	Code    SandboxNetworkProxyValidationCode `json:"code"`
	Field   string                            `json:"field,omitempty"`
	Message string                            `json:"message,omitempty"`
}

// SandboxNetworkProxyValidationResult is the deterministic output of pure
// proxy-session metadata validation and normalization.
type SandboxNetworkProxyValidationResult struct {
	Valid      bool                                 `json:"valid"`
	Normalized *SandboxNetworkProxySessionMetadata  `json:"normalized,omitempty"`
	Errors     []SandboxNetworkProxyValidationError `json:"errors,omitempty"`
}

// ValidateAndNormalizeSandboxNetworkProxySessionMetadata validates durable
// proxy-session metadata without inspecting hosts, starting listeners, or
// inferring runtime enforcement capability.
func ValidateAndNormalizeSandboxNetworkProxySessionMetadata(session SandboxNetworkProxySessionMetadata) SandboxNetworkProxyValidationResult {
	normalized := normalizeSandboxNetworkProxySessionMetadata(session)
	result := SandboxNetworkProxyValidationResult{Valid: true}

	if normalized.ID == "" {
		result.addError("id", SandboxNetworkProxyValidationMissingRequiredField, "proxy session id is required")
	}
	if normalized.Source == "" {
		result.addError("source", SandboxNetworkProxyValidationMissingRequiredField, "proxy session source is required")
	} else if !validSandboxNetworkPolicyDecisionSource(normalized.Source) {
		result.addError("source", SandboxNetworkProxyValidationInvalidSource, "proxy session source is unsupported")
	}
	if normalized.PolicySnapshot != nil {
		if normalized.PolicySnapshot.ID == "" {
			result.addError("policySnapshot.id", SandboxNetworkProxyValidationMissingRequiredField, "policy snapshot id is required")
		}
		if normalized.PolicySnapshot.Preset != "" && !validSandboxNetworkPolicyPreset(normalized.PolicySnapshot.Preset) {
			result.addError("policySnapshot.preset", SandboxNetworkProxyValidationInvalidPolicyPreset, "policy snapshot preset is unsupported")
		}
	}
	if normalized.EnforcementMode != "" && !validSandboxNetworkProxyEnforcementMode(normalized.EnforcementMode) {
		result.addError("enforcementMode", SandboxNetworkProxyValidationInvalidEnforcement, "proxy enforcement mode is unsupported")
	}

	if len(result.Errors) > 0 {
		result.Valid = false
		return result
	}
	result.Normalized = &normalized
	return result
}

func normalizeSandboxNetworkProxySessionMetadata(session SandboxNetworkProxySessionMetadata) SandboxNetworkProxySessionMetadata {
	normalized := SandboxNetworkProxySessionMetadata{
		ID:              strings.TrimSpace(session.ID),
		Source:          normalizeSandboxNetworkPolicyDecisionSource(session.Source),
		EnforcementMode: normalizeSandboxNetworkProxyEnforcementMode(session.EnforcementMode),
	}
	if session.PolicySnapshot != nil {
		normalized.PolicySnapshot = &SandboxNetworkPolicySnapshotIdentity{
			ID:        strings.TrimSpace(session.PolicySnapshot.ID),
			Version:   strings.TrimSpace(session.PolicySnapshot.Version),
			Preset:    normalizeSandboxNetworkPolicyPreset(session.PolicySnapshot.Preset),
			RuleSetID: strings.TrimSpace(session.PolicySnapshot.RuleSetID),
		}
	}
	return normalized
}

func normalizeSandboxNetworkPolicyDecisionSource(source SandboxNetworkPolicyDecisionSource) SandboxNetworkPolicyDecisionSource {
	return SandboxNetworkPolicyDecisionSource(strings.ToLower(strings.TrimSpace(string(source))))
}

func normalizeSandboxNetworkPolicyPreset(preset SandboxNetworkPolicyPreset) SandboxNetworkPolicyPreset {
	return SandboxNetworkPolicyPreset(strings.ToLower(strings.TrimSpace(string(preset))))
}

func normalizeSandboxNetworkProxyEnforcementMode(mode string) string {
	return strings.ToLower(strings.TrimSpace(mode))
}

func validSandboxNetworkPolicyDecisionSource(source SandboxNetworkPolicyDecisionSource) bool {
	switch source {
	case SandboxNetworkPolicyDecisionSourceRun,
		SandboxNetworkPolicyDecisionSourceAuto,
		SandboxNetworkPolicyDecisionSourceFactory,
		SandboxNetworkPolicyDecisionSourceWorker:
		return true
	default:
		return false
	}
}

func validSandboxNetworkProxyEnforcementMode(mode string) bool {
	switch mode {
	case SandboxNetworkEnforcementModeNone,
		SandboxNetworkEnforcementModeBestEffort,
		SandboxNetworkEnforcementModeProxy,
		SandboxNetworkEnforcementModeFirewall,
		SandboxNetworkEnforcementModeRuntime,
		SandboxNetworkEnforcementModeProxyFirewall:
		return true
	default:
		return false
	}
}

func (r *SandboxNetworkProxyValidationResult) addError(field string, code SandboxNetworkProxyValidationCode, message string) {
	r.Errors = append(r.Errors, SandboxNetworkProxyValidationError{
		Code:    code,
		Field:   field,
		Message: message,
	})
}
