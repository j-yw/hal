package credentialdelivery

import "strings"

// ValidateBindingMetadata validates one credential delivery binding using only
// data-local safety checks. It does not validate request-level invariants such
// as duplicate binding IDs.
func ValidateBindingMetadata(binding Binding) ValidationResult {
	result := ValidationResult{Valid: true}

	result.validateRequiredID("id", binding.ID)
	result.validateOptionalReference("requestId", binding.RequestID)
	result.validateOptionalReference("planId", binding.PlanID)
	result.validateOptionalReference("policySnapshotId", binding.PolicySnapshotID)
	result.validateRequiredSecretReference("secretRef", binding.SecretRef)
	result.validateOptionalReference("networkProxySessionId", binding.NetworkProxySessionID)
	result.validateOptionalReference("serviceId", binding.ServiceID)
	result.validateOptionalLabels("serviceLabels", binding.ServiceLabels)
	result.validateOptionalLabels("domainLabels", binding.DomainLabels)
	result.validateOptionalDestinationCategory("destinationCategory", binding.DestinationCategory)
	result.validateRequiredMode("deliveryMode", binding.DeliveryMode)
	result.validateOptionalStatus("status", binding.Status)
	result.validateOptionalReasonCode("reasonCode", binding.ReasonCode)

	result.Valid = len(result.Errors) == 0
	return result
}

func (r *ValidationResult) validateRequiredID(field, value string) {
	if strings.TrimSpace(value) == "" {
		r.addError(field, ErrorMissingRequiredField, nil)
		return
	}
	if unsafeCredentialDeliveryIdentifier(value) {
		r.addError(field, ErrorUnsafeReference, nil)
	}
}

func (r *ValidationResult) validateOptionalReference(field, value string) {
	if value == "" {
		return
	}
	if strings.TrimSpace(value) == "" || unsafeCredentialDeliveryIdentifier(value) {
		r.addError(field, ErrorUnsafeReference, nil)
	}
}

func (r *ValidationResult) validateRequiredSecretReference(field, value string) {
	if strings.TrimSpace(value) == "" {
		r.addError(field, ErrorMissingRequiredField, nil)
		return
	}
	if unsafeCredentialDeliverySecretReference(value) {
		r.addError(field, ErrorUnsafeReference, nil)
	}
}

func (r *ValidationResult) validateOptionalLabels(field string, values []string) {
	for i, value := range values {
		if strings.TrimSpace(value) == "" || unsafeCredentialDeliveryLabel(value) {
			r.addError(field, ErrorUnsafeMetadata, &i)
		}
	}
}

func (r *ValidationResult) validateOptionalDestinationCategory(field string, value DestinationCategory) {
	if value == "" {
		return
	}
	if unsafeCredentialDeliveryFreeformMetadata(string(value)) {
		r.addError(field, ErrorUnsafeMetadata, nil)
		return
	}
	if !validDestinationCategory(value) {
		r.addError(field, ErrorUnsupportedCategory, nil)
	}
}

func (r *ValidationResult) validateRequiredMode(field string, value Mode) {
	if strings.TrimSpace(string(value)) == "" {
		r.addError(field, ErrorMissingRequiredField, nil)
		return
	}
	if unsafeCredentialDeliveryFreeformMetadata(string(value)) {
		r.addError(field, ErrorUnsafeMetadata, nil)
		return
	}
	if !validMode(value) {
		r.addError(field, ErrorUnsupportedMode, nil)
	}
}

func (r *ValidationResult) validateOptionalStatus(field string, value Status) {
	if value == "" {
		return
	}
	if unsafeCredentialDeliveryFreeformMetadata(string(value)) || !validStatus(value) {
		r.addError(field, ErrorUnsafeMetadata, nil)
	}
}

func (r *ValidationResult) validateOptionalReasonCode(field string, value ReasonCode) {
	if value == "" {
		return
	}
	if unsafeCredentialDeliveryFreeformMetadata(string(value)) || !validReasonCode(value) {
		r.addError(field, ErrorUnsafeMetadata, nil)
	}
}

func (r *ValidationResult) addError(field string, code ErrorCode, index *int) {
	err := SanitizedError{
		Code:  code,
		Field: field,
	}
	if index != nil {
		idx := *index
		err.Index = &idx
	}
	r.Errors = append(r.Errors, err)
}

func unsafeCredentialDeliveryIdentifier(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || unsafeCredentialDeliveryFreeformMetadata(value) {
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

func unsafeCredentialDeliverySecretReference(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || credentialDeliveryContainsControl(value) {
		return true
	}
	if !unsafeCredentialDeliveryIdentifier(value) {
		return false
	}

	source, name, ok := strings.Cut(value, ":")
	if !ok || strings.Contains(name, ":") {
		return true
	}
	return unsafeCredentialDeliveryIdentifier(source) || !safeCredentialDeliveryBrokerSecretName(name)
}

func safeCredentialDeliveryBrokerSecretName(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || credentialDeliveryContainsControl(value) {
		return false
	}
	for i, r := range value {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9' && i > 0:
		case r == '_':
		default:
			return false
		}
	}
	return true
}

func unsafeCredentialDeliveryLabel(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || unsafeCredentialDeliveryFreeformMetadata(value) {
		return true
	}
	if value[0] == '-' || value[0] == '_' || value[len(value)-1] == '-' || value[len(value)-1] == '_' {
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

func unsafeCredentialDeliveryFreeformMetadata(value string) bool {
	if value == "" {
		return false
	}
	if value != strings.TrimSpace(value) || credentialDeliveryContainsControl(value) || credentialDeliveryAllDigits(value) {
		return true
	}
	if credentialDeliveryContainsUnsafeMetadataMarker(value) {
		return true
	}
	return strings.Contains(value, ".") || strings.ContainsAny(value, "/\\?#\"'`{}[]()<>|;&=$:@")
}

func unsafeCredentialDeliveryFieldPath(value string) bool {
	if value == "" {
		return false
	}
	if value != strings.TrimSpace(value) || credentialDeliveryContainsControl(value) || credentialDeliveryAllDigits(value) {
		return true
	}
	if credentialDeliveryContainsUnsafeMetadataMarker(value) {
		return true
	}
	if value[0] == '.' || value[len(value)-1] == '.' || strings.Contains(value, "..") {
		return true
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return true
		}
	}
	return false
}

func credentialDeliveryContainsUnsafeMetadataMarker(value string) bool {
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "ghp_") ||
		strings.HasPrefix(lower, "github_pat_") ||
		strings.HasPrefix(lower, "sk-") {
		return true
	}
	for _, marker := range []string{
		"://",
		"authorization",
		"proxy-authorization",
		"bearer",
		"cookie",
		"set-cookie",
		"token",
		"password",
		"passwd",
		"api_key",
		"api-key",
		"apikey",
		"access_key",
		"access-key",
		"private_key",
		"private-key",
		"secretvalue",
		"secret_value",
		"secret-value",
		"credentialvalue",
		"credential_value",
		"credential-value",
		"providercredential",
		"provider_credential",
		"provider-credential",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func credentialDeliveryContainsControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func credentialDeliveryAllDigits(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return value != ""
}

func validMode(value Mode) bool {
	for _, mode := range SupportedModes() {
		if value == mode {
			return true
		}
	}
	return false
}

func validDestinationCategory(value DestinationCategory) bool {
	for _, category := range SupportedDestinationCategories() {
		if value == category {
			return true
		}
	}
	return false
}

func validStatus(value Status) bool {
	switch value {
	case StatusRequested,
		StatusPlanned,
		StatusReady,
		StatusActive,
		StatusCompleted,
		StatusSkipped,
		StatusFailed,
		StatusDisabled:
		return true
	default:
		return false
	}
}

func validReasonCode(value ReasonCode) bool {
	switch value {
	case ReasonRequested,
		ReasonUnsupportedMode,
		ReasonMissingSecretReference,
		ReasonMissingServiceBinding,
		ReasonMissingActivationProof,
		ReasonUnsupportedCapability,
		ReasonActivationUnavailable,
		ReasonCompatibilityMode,
		ReasonDisabled,
		ReasonUnknown:
		return true
	default:
		return false
	}
}

func validWarningCode(value WarningCode) bool {
	switch value {
	case WarningUnsupportedMode,
		WarningBindingOmitted,
		WarningActivationSkipped,
		WarningAdapterUnavailable,
		WarningCompatibilityMode,
		WarningLegacyAuthCompatibility:
		return true
	default:
		return false
	}
}

func validErrorCode(value ErrorCode) bool {
	switch value {
	case ErrorMissingRequiredField,
		ErrorMissingSecretReference,
		ErrorUnsupportedMode,
		ErrorUnsupportedCategory,
		ErrorUnsafeReference,
		ErrorUnsafeMetadata,
		ErrorDuplicateBinding,
		ErrorResolverFailed,
		ErrorActivationFailed:
		return true
	default:
		return false
	}
}
