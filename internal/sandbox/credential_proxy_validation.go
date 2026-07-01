package sandbox

import "strings"

// SandboxCredentialProxyValidationCode identifies a sanitized credential proxy
// metadata validation failure. Codes must not include rejected input values.
type SandboxCredentialProxyValidationCode string

const (
	SandboxCredentialProxyValidationMissingRequiredID    SandboxCredentialProxyValidationCode = "missing_required_id"
	SandboxCredentialProxyValidationMissingRequiredField SandboxCredentialProxyValidationCode = "missing_required_field"
	SandboxCredentialProxyValidationUnsafeID             SandboxCredentialProxyValidationCode = "unsafe_id"
	SandboxCredentialProxyValidationUnsafeReference      SandboxCredentialProxyValidationCode = "unsafe_reference"
	SandboxCredentialProxyValidationUnsafeMetadata       SandboxCredentialProxyValidationCode = "unsafe_metadata"
	SandboxCredentialProxyValidationInvalidEnum          SandboxCredentialProxyValidationCode = "invalid_enum"
)

// SandboxCredentialProxyValidationError identifies invalid metadata by safe
// field name only.
type SandboxCredentialProxyValidationError struct {
	Code    SandboxCredentialProxyValidationCode `json:"code"`
	Field   string                               `json:"field,omitempty"`
	Message string                               `json:"message,omitempty"`
}

// SandboxCredentialProxyValidationResult is the deterministic output of pure
// credential proxy metadata validation.
type SandboxCredentialProxyValidationResult struct {
	Valid  bool                                    `json:"valid"`
	Errors []SandboxCredentialProxyValidationError `json:"errors,omitempty"`
}

// ValidateSandboxCredentialProxyPlanMetadata validates durable plan metadata
// without resolving secret broker or network proxy state.
func ValidateSandboxCredentialProxyPlanMetadata(plan SandboxCredentialProxyPlanMetadata) SandboxCredentialProxyValidationResult {
	result := SandboxCredentialProxyValidationResult{Valid: true}

	result.validateRequiredID("id", plan.ID, SandboxCredentialProxyValidationUnsafeID, "credential proxy plan id is required")
	result.validateRequiredEnum("source", string(plan.Source), validSandboxCredentialProxySource, "credential proxy source is required", "credential proxy source is unsupported")
	result.validateOptionalReference("secretBrokerSessionId", plan.SecretBrokerSessionID, "secret broker session id must be a safe reference")
	result.validateOptionalReference("networkProxySessionId", plan.NetworkProxySessionID, "network proxy session id must be a safe reference")
	result.validatePolicySnapshot(plan.PolicySnapshot)
	result.validateOptionalEnum("mode", string(plan.Mode), validSandboxCredentialProxyMode, "credential proxy mode is unsupported")
	result.validateOptionalEnum("status", string(plan.Status), validSandboxCredentialProxyStatus, "credential proxy status is unsupported")

	result.Valid = len(result.Errors) == 0
	return result
}

// ValidateSandboxCredentialProxySessionMetadata validates durable session
// metadata without resolving external state.
func ValidateSandboxCredentialProxySessionMetadata(session SandboxCredentialProxySessionMetadata) SandboxCredentialProxyValidationResult {
	result := SandboxCredentialProxyValidationResult{Valid: true}

	result.validateRequiredID("id", session.ID, SandboxCredentialProxyValidationUnsafeID, "credential proxy session id is required")
	result.validateRequiredID("planId", session.PlanID, SandboxCredentialProxyValidationUnsafeReference, "credential proxy plan id is required")
	result.validateRequiredEnum("source", string(session.Source), validSandboxCredentialProxySource, "credential proxy source is required", "credential proxy source is unsupported")
	result.validateOptionalReference("secretBrokerSessionId", session.SecretBrokerSessionID, "secret broker session id must be a safe reference")
	result.validateOptionalReference("networkProxySessionId", session.NetworkProxySessionID, "network proxy session id must be a safe reference")
	result.validatePolicySnapshot(session.PolicySnapshot)
	result.validateOptionalEnum("status", string(session.Status), validSandboxCredentialProxyStatus, "credential proxy status is unsupported")
	result.validateOptionalEnum("warningCode", string(session.WarningCode), validSandboxCredentialProxyWarningCode, "credential proxy warning code is unsupported")
	result.validateOptionalEnum("reasonCode", string(session.ReasonCode), validSandboxCredentialProxyReasonCode, "credential proxy reason code is unsupported")

	result.Valid = len(result.Errors) == 0
	return result
}

// ValidateSandboxCredentialProxyBindingMetadata validates durable binding
// metadata using only safe IDs and enum-like labels.
func ValidateSandboxCredentialProxyBindingMetadata(binding SandboxCredentialProxyBindingMetadata) SandboxCredentialProxyValidationResult {
	result := SandboxCredentialProxyValidationResult{Valid: true}

	result.validateRequiredID("id", binding.ID, SandboxCredentialProxyValidationUnsafeID, "credential proxy binding id is required")
	if strings.TrimSpace(binding.PlanID) == "" && strings.TrimSpace(binding.SessionID) == "" {
		result.addError("planId", SandboxCredentialProxyValidationMissingRequiredField, "credential proxy binding requires a plan or session reference")
	}
	result.validateOptionalReference("planId", binding.PlanID, "credential proxy plan id must be a safe reference")
	result.validateOptionalReference("sessionId", binding.SessionID, "credential proxy session id must be a safe reference")
	result.validateRequiredID("secretId", binding.SecretID, SandboxCredentialProxyValidationUnsafeReference, "credential proxy secret id is required")
	result.validateRequiredEnum("deliveryMode", string(binding.DeliveryMode), validSandboxCredentialProxyDeliveryMode, "credential proxy delivery mode is required", "credential proxy delivery mode is unsupported")
	result.validateOptionalEnum("requestCategory", string(binding.RequestCategory), validSandboxCredentialProxyRequestCategory, "credential proxy request category is unsupported")
	result.validateOptionalEnum("destinationCategory", string(binding.DestinationCategory), validSandboxCredentialProxyDestinationCategory, "credential proxy destination category is unsupported")
	result.validateOptionalEnum("outcome", string(binding.Outcome), validSandboxCredentialProxyBindingOutcome, "credential proxy binding outcome is unsupported")
	result.validateOptionalEnum("status", string(binding.Status), validSandboxCredentialProxyStatus, "credential proxy status is unsupported")
	result.validateOptionalEnum("reasonCode", string(binding.ReasonCode), validSandboxCredentialProxyReasonCode, "credential proxy reason code is unsupported")

	result.Valid = len(result.Errors) == 0
	return result
}

func (r *SandboxCredentialProxyValidationResult) validateRequiredID(field, value string, unsafeCode SandboxCredentialProxyValidationCode, missingMessage string) {
	if strings.TrimSpace(value) == "" {
		r.addError(field, SandboxCredentialProxyValidationMissingRequiredID, missingMessage)
		return
	}
	if unsafeSandboxCredentialProxyIdentifier(value) {
		r.addError(field, unsafeCode, "credential proxy identifier must be a safe value")
	}
}

func (r *SandboxCredentialProxyValidationResult) validateOptionalReference(field, value, message string) {
	if value == "" {
		return
	}
	if strings.TrimSpace(value) == "" || unsafeSandboxCredentialProxyIdentifier(value) {
		r.addError(field, SandboxCredentialProxyValidationUnsafeReference, message)
	}
}

func (r *SandboxCredentialProxyValidationResult) validatePolicySnapshot(snapshot *SandboxNetworkPolicySnapshotIdentity) {
	if snapshot == nil {
		return
	}
	r.validateRequiredID("policySnapshot.id", snapshot.ID, SandboxCredentialProxyValidationUnsafeReference, "policy snapshot id is required")
	r.validateOptionalReference("policySnapshot.version", snapshot.Version, "policy snapshot version must be a safe reference")
	r.validateOptionalReference("policySnapshot.ruleSetId", snapshot.RuleSetID, "policy snapshot rule set id must be a safe reference")
	r.validateOptionalEnum("policySnapshot.preset", string(snapshot.Preset), validSandboxCredentialProxyPolicyPreset, "policy snapshot preset is unsupported")
}

func (r *SandboxCredentialProxyValidationResult) validateRequiredEnum(field, value string, valid func(string) bool, missingMessage, invalidMessage string) {
	if strings.TrimSpace(value) == "" {
		r.addError(field, SandboxCredentialProxyValidationMissingRequiredField, missingMessage)
		return
	}
	if unsafeSandboxCredentialProxyFreeformMetadata(value) {
		r.addError(field, SandboxCredentialProxyValidationUnsafeMetadata, invalidMessage)
		return
	}
	if !valid(value) {
		r.addError(field, SandboxCredentialProxyValidationInvalidEnum, invalidMessage)
	}
}

func (r *SandboxCredentialProxyValidationResult) validateOptionalEnum(field, value string, valid func(string) bool, invalidMessage string) {
	if value == "" {
		return
	}
	if strings.TrimSpace(value) == "" || unsafeSandboxCredentialProxyFreeformMetadata(value) {
		r.addError(field, SandboxCredentialProxyValidationUnsafeMetadata, invalidMessage)
		return
	}
	if !valid(value) {
		r.addError(field, SandboxCredentialProxyValidationInvalidEnum, invalidMessage)
	}
}

func (r *SandboxCredentialProxyValidationResult) addError(field string, code SandboxCredentialProxyValidationCode, message string) {
	r.Errors = append(r.Errors, SandboxCredentialProxyValidationError{
		Code:    code,
		Field:   field,
		Message: message,
	})
}

func unsafeSandboxCredentialProxyIdentifier(value string) bool {
	if value != strings.TrimSpace(value) || unsafeSandboxCredentialProxyFreeformMetadata(value) {
		return true
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return true
		}
	}
	return false
}

func unsafeSandboxCredentialProxyFreeformMetadata(value string) bool {
	if value == "" {
		return false
	}
	if value != strings.TrimSpace(value) || sandboxCredentialProxyContainsControl(value) || sandboxCredentialProxyAllDigits(value) {
		return true
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"://",
		"authorization",
		"bearer",
		"cookie",
		"token",
		"password",
		"api_key",
		"apikey",
		"access_key",
		"private_key",
		"secretvalue",
		"secret_value",
		"credentialvalue",
		"credential_value",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return strings.Contains(value, ".") || strings.ContainsAny(value, "/\\?#\"'`{}[]()<>|;&=$:")
}

func sandboxCredentialProxyContainsControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func sandboxCredentialProxyAllDigits(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return value != ""
}

func validSandboxCredentialProxySource(value string) bool {
	switch SandboxCredentialProxySource(value) {
	case SandboxCredentialProxySourceRun,
		SandboxCredentialProxySourceAuto,
		SandboxCredentialProxySourceFactory,
		SandboxCredentialProxySourceWorker:
		return true
	default:
		return false
	}
}

func validSandboxCredentialProxyMode(value string) bool {
	switch SandboxCredentialProxyMode(value) {
	case SandboxCredentialProxyModeMetadataOnly,
		SandboxCredentialProxyModeSecretBrokerReference,
		SandboxCredentialProxyModeNetworkProxyReference,
		SandboxCredentialProxyModeBrokeredNetworkReference:
		return true
	default:
		return false
	}
}

func validSandboxCredentialProxyStatus(value string) bool {
	switch SandboxCredentialProxyStatus(value) {
	case SandboxCredentialProxyStatusPlanned,
		SandboxCredentialProxyStatusReady,
		SandboxCredentialProxyStatusActive,
		SandboxCredentialProxyStatusCompleted,
		SandboxCredentialProxyStatusSkipped,
		SandboxCredentialProxyStatusFailed,
		SandboxCredentialProxyStatusDisabled:
		return true
	default:
		return false
	}
}

func validSandboxCredentialProxyBindingOutcome(value string) bool {
	switch SandboxCredentialProxyBindingOutcome(value) {
	case SandboxCredentialProxyBindingOutcomePlanned,
		SandboxCredentialProxyBindingOutcomeBound,
		SandboxCredentialProxyBindingOutcomeOmitted,
		SandboxCredentialProxyBindingOutcomeSkipped,
		SandboxCredentialProxyBindingOutcomeFailed,
		SandboxCredentialProxyBindingOutcomeAuditOnly:
		return true
	default:
		return false
	}
}

func validSandboxCredentialProxyWarningCode(value string) bool {
	switch SandboxCredentialProxyWarningCode(value) {
	case SandboxCredentialProxyWarningMissingSecretBrokerSession,
		SandboxCredentialProxyWarningMissingNetworkProxySession,
		SandboxCredentialProxyWarningPolicySnapshotUnavailable,
		SandboxCredentialProxyWarningUnsupportedDeliveryMode,
		SandboxCredentialProxyWarningBindingOmitted:
		return true
	default:
		return false
	}
}

func validSandboxCredentialProxyReasonCode(value string) bool {
	switch SandboxCredentialProxyReasonCode(value) {
	case SandboxCredentialProxyReasonRequested,
		SandboxCredentialProxyReasonSecretBrokerUnavailable,
		SandboxCredentialProxyReasonNetworkProxyUnavailable,
		SandboxCredentialProxyReasonPolicySnapshotUnavailable,
		SandboxCredentialProxyReasonDeliveryModeUnsupported,
		SandboxCredentialProxyReasonDestinationCategorySkipped,
		SandboxCredentialProxyReasonDisabled,
		SandboxCredentialProxyReasonUnknown:
		return true
	default:
		return false
	}
}

func validSandboxCredentialProxyDeliveryMode(value string) bool {
	switch SandboxCredentialProxyDeliveryMode(value) {
	case SandboxCredentialProxyDeliveryModeEnv,
		SandboxCredentialProxyDeliveryModeFileTmpfs,
		SandboxCredentialProxyDeliveryModeSSHAgent,
		SandboxCredentialProxyDeliveryModeHTTPProxy,
		SandboxCredentialProxyDeliveryModeLegacyAuthSync:
		return true
	default:
		return false
	}
}

func validSandboxCredentialProxyRequestCategory(value string) bool {
	switch SandboxCredentialProxyRequestCategory(value) {
	case SandboxCredentialProxyRequestSecretDelivery,
		SandboxCredentialProxyRequestNetworkAuth,
		SandboxCredentialProxyRequestSourceControl,
		SandboxCredentialProxyRequestArtifactSync,
		SandboxCredentialProxyRequestUnknown:
		return true
	default:
		return false
	}
}

func validSandboxCredentialProxyDestinationCategory(value string) bool {
	return validSandboxNetworkPolicyDestinationCategory(SandboxNetworkPolicyDestinationCategory(value))
}

func validSandboxCredentialProxyPolicyPreset(value string) bool {
	return validSandboxNetworkPolicyPreset(SandboxNetworkPolicyPreset(value))
}
