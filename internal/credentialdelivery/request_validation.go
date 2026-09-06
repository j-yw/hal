package credentialdelivery

import "strings"

// ValidateRequestMetadata validates a credential delivery request using only
// safe metadata checks. It does not resolve credentials or invoke adapters.
func ValidateRequestMetadata(request Request) ValidationResult {
	result := ValidationResult{Valid: true}

	result.validateRequiredID("id", request.ID)
	result.validateOptionalSource("source", request.Source)
	result.validateOptionalModes("requestedModes", request.RequestedModes)
	result.validateOptionalModes("activeModes", request.ActiveModes)
	result.validateOptionalStatus("status", request.Status)
	result.validateRequestBindings(request.Bindings)

	result.Valid = len(result.Errors) == 0
	return result
}

func (r *ValidationResult) validateOptionalSource(field string, value Source) {
	if value == "" {
		return
	}
	raw := string(value)
	if strings.TrimSpace(raw) == "" || unsafeCredentialDeliveryFreeformMetadata(raw) || !validSource(value) {
		r.addError(field, ErrorUnsafeMetadata, nil)
	}
}

func (r *ValidationResult) validateOptionalModes(field string, values []Mode) {
	for i, value := range values {
		r.validateModeAt(field, value, i)
	}
}

func (r *ValidationResult) validateModeAt(field string, value Mode, index int) {
	raw := string(value)
	if strings.TrimSpace(raw) == "" {
		r.addError(field, ErrorMissingRequiredField, &index)
		return
	}
	if unsafeCredentialDeliveryFreeformMetadata(raw) {
		r.addError(field, ErrorUnsafeMetadata, &index)
		return
	}
	if !validMode(value) {
		r.addError(field, ErrorUnsupportedMode, &index)
	}
}

func (r *ValidationResult) validateRequestBindings(bindings []Binding) {
	seenBindingIDs := make(map[string]struct{}, len(bindings))
	for i, binding := range bindings {
		bindingResult := ValidateBindingMetadata(binding)
		for _, err := range bindingResult.Errors {
			r.addBindingValidationError(i, err)
		}

		if strings.TrimSpace(binding.ID) == "" || unsafeCredentialDeliveryIdentifier(binding.ID) {
			continue
		}
		if _, ok := seenBindingIDs[binding.ID]; ok {
			r.addError("bindings.id", ErrorDuplicateBinding, &i)
			continue
		}
		seenBindingIDs[binding.ID] = struct{}{}
	}
}

func (r *ValidationResult) addBindingValidationError(bindingIndex int, err SanitizedError) {
	field := "bindings"
	if err.Field != "" {
		field += "." + err.Field
	}
	r.addError(field, err.Code, &bindingIndex)
}

func validSource(value Source) bool {
	switch value {
	case SourceRun,
		SourceAuto,
		SourceFactory,
		SourceWorker,
		SourceRuntime:
		return true
	default:
		return false
	}
}
