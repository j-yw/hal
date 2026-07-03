package credentialdelivery

// SanitizeRequestMetadata returns a durable-safe copy of credential delivery
// request metadata. A missing or unsafe required ID returns the zero value so
// callers can omit the record before persistence.
func SanitizeRequestMetadata(request Request) Request {
	sanitized := NormalizeRequestMetadata(request)
	sanitized.ID = sanitizeIdentifier(sanitized.ID)
	if sanitized.ID == "" {
		return Request{}
	}
	sanitized.Source = sanitizeSourceValue(sanitized.Source)
	sanitized.RequestedModes = sanitizeOptionalModeRecords(sanitized.RequestedModes)
	sanitized.ActiveModes = sanitizeOptionalModeRecords(sanitized.ActiveModes)
	sanitized.Bindings = SanitizeBindingMetadataRecords(sanitized.Bindings)
	sanitized.Status = sanitizeStatusValue(sanitized.Status)
	return sanitized
}

// SanitizeBindingMetadata returns a durable-safe copy of credential delivery
// binding metadata. Missing or unsafe required fields return the zero value so
// callers can omit the record before persistence.
func SanitizeBindingMetadata(binding Binding) Binding {
	sanitized := NormalizeBindingMetadata(binding)
	sanitized.ID = sanitizeIdentifier(sanitized.ID)
	sanitized.SecretRef = sanitizeSecretReference(sanitized.SecretRef)
	sanitized.DeliveryMode = sanitizeRequiredModeValue(sanitized.DeliveryMode)
	if sanitized.ID == "" || sanitized.SecretRef == "" || sanitized.DeliveryMode == "" {
		return Binding{}
	}
	sanitized.RequestID = sanitizeIdentifier(sanitized.RequestID)
	sanitized.PlanID = sanitizeIdentifier(sanitized.PlanID)
	sanitized.PolicySnapshotID = sanitizeIdentifier(sanitized.PolicySnapshotID)
	sanitized.NetworkProxySessionID = sanitizeIdentifier(sanitized.NetworkProxySessionID)
	sanitized.ServiceID = sanitizeIdentifier(sanitized.ServiceID)
	sanitized.ServiceLabels = sanitizeLabelRecords(sanitized.ServiceLabels)
	sanitized.DomainLabels = sanitizeLabelRecords(sanitized.DomainLabels)
	sanitized.DestinationCategory = sanitizeDestinationCategoryValue(sanitized.DestinationCategory)
	sanitized.Status = sanitizeStatusValue(sanitized.Status)
	sanitized.ReasonCode = sanitizeReasonCodeValue(sanitized.ReasonCode)
	return sanitized
}

// SanitizeBindingMetadataRecords returns durable-safe binding records, omitting
// entries whose required metadata is missing or unsafe while preserving nil
// versus explicit empty input slices.
func SanitizeBindingMetadataRecords(bindings []Binding) []Binding {
	if bindings == nil {
		return nil
	}
	sanitized := make([]Binding, 0, len(bindings))
	for _, binding := range bindings {
		record := SanitizeBindingMetadata(binding)
		if record.ID != "" {
			sanitized = append(sanitized, record)
		}
	}
	return sanitized
}

// SanitizePlanMetadata returns a durable-safe copy of delivery plan metadata.
// A missing or unsafe required ID returns the zero value.
func SanitizePlanMetadata(plan Plan) Plan {
	sanitized := NormalizePlanMetadata(plan)
	sanitized.ID = sanitizeIdentifier(sanitized.ID)
	if sanitized.ID == "" {
		return Plan{}
	}
	sanitized.RequestID = sanitizeIdentifier(sanitized.RequestID)
	sanitized.RequestedModes = sanitizeOptionalModeRecords(sanitized.RequestedModes)
	sanitized.ActiveModes = sanitizeOptionalModeRecords(sanitized.ActiveModes)
	sanitized.Status = sanitizeStatusValue(sanitized.Status)
	sanitized.Warnings = SanitizeWarningMetadataRecords(sanitized.Warnings)
	sanitized.Errors = SanitizeSanitizedErrorRecords(sanitized.Errors)
	return sanitized
}

// SanitizeActivationResultMetadata returns a durable-safe copy of delivery
// activation metadata. Missing or unsafe required IDs return the zero value.
func SanitizeActivationResultMetadata(result ActivationResult) ActivationResult {
	sanitized := NormalizeActivationResultMetadata(result)
	sanitized.ID = sanitizeIdentifier(sanitized.ID)
	sanitized.PlanID = sanitizeIdentifier(sanitized.PlanID)
	if sanitized.ID == "" || sanitized.PlanID == "" {
		return ActivationResult{}
	}
	sanitized.RequestedModes = sanitizeOptionalModeRecords(sanitized.RequestedModes)
	sanitized.ActiveModes = sanitizeOptionalModeRecords(sanitized.ActiveModes)
	sanitized.Bindings = SanitizeBindingActivationResultMetadataRecords(sanitized.Bindings)
	sanitized.Status = sanitizeStatusValue(sanitized.Status)
	sanitized.Warnings = SanitizeWarningMetadataRecords(sanitized.Warnings)
	sanitized.Errors = SanitizeSanitizedErrorRecords(sanitized.Errors)
	return sanitized
}

// SanitizeBindingActivationResultMetadata returns a durable-safe copy of one
// binding activation record. Missing or unsafe required metadata returns zero.
func SanitizeBindingActivationResultMetadata(result BindingActivationResult) BindingActivationResult {
	sanitized := NormalizeBindingActivationResultMetadata(result)
	sanitized.BindingID = sanitizeIdentifier(sanitized.BindingID)
	sanitized.DeliveryMode = sanitizeRequiredModeValue(sanitized.DeliveryMode)
	if sanitized.BindingID == "" || sanitized.DeliveryMode == "" {
		return BindingActivationResult{}
	}
	sanitized.Status = sanitizeStatusValue(sanitized.Status)
	sanitized.ReasonCode = sanitizeReasonCodeValue(sanitized.ReasonCode)
	return sanitized
}

// SanitizeBindingActivationResultMetadataRecords returns durable-safe binding
// activation records while preserving nil versus explicit empty input slices.
func SanitizeBindingActivationResultMetadataRecords(results []BindingActivationResult) []BindingActivationResult {
	if results == nil {
		return nil
	}
	sanitized := make([]BindingActivationResult, 0, len(results))
	for _, result := range results {
		record := SanitizeBindingActivationResultMetadata(result)
		if record.BindingID != "" {
			sanitized = append(sanitized, record)
		}
	}
	return sanitized
}

// SanitizeStatusMetadata returns a durable-safe copy of compact delivery
// lifecycle status metadata. Missing or unsafe required IDs return zero.
func SanitizeStatusMetadata(status StatusMetadata) StatusMetadata {
	sanitized := NormalizeStatusMetadata(status)
	sanitized.ID = sanitizeIdentifier(sanitized.ID)
	if sanitized.ID == "" {
		return StatusMetadata{}
	}
	sanitized.RequestID = sanitizeIdentifier(sanitized.RequestID)
	sanitized.PlanID = sanitizeIdentifier(sanitized.PlanID)
	sanitized.ActivationID = sanitizeIdentifier(sanitized.ActivationID)
	sanitized.RequestedModes = sanitizeOptionalModeRecords(sanitized.RequestedModes)
	sanitized.ActiveModes = sanitizeOptionalModeRecords(sanitized.ActiveModes)
	sanitized.Status = sanitizeStatusValue(sanitized.Status)
	sanitized.ReasonCode = sanitizeReasonCodeValue(sanitized.ReasonCode)
	return sanitized
}

// SanitizeWarningMetadata returns a durable-safe copy of warning metadata.
// Missing or unsafe required warning codes return the zero value.
func SanitizeWarningMetadata(warning Warning) Warning {
	sanitized := NormalizeWarningMetadata(warning)
	sanitized.Code = sanitizeWarningCodeValue(sanitized.Code)
	if sanitized.Code == "" {
		return Warning{}
	}
	sanitized.ReasonCode = sanitizeReasonCodeValue(sanitized.ReasonCode)
	sanitized.BindingID = sanitizeIdentifier(sanitized.BindingID)
	sanitized.Mode = sanitizeOptionalModeValue(sanitized.Mode)
	return sanitized
}

// SanitizeWarningMetadataRecords returns durable-safe warning records while
// preserving nil versus explicit empty input slices.
func SanitizeWarningMetadataRecords(warnings []Warning) []Warning {
	if warnings == nil {
		return nil
	}
	sanitized := make([]Warning, 0, len(warnings))
	for _, warning := range warnings {
		record := SanitizeWarningMetadata(warning)
		if record.Code != "" {
			sanitized = append(sanitized, record)
		}
	}
	return sanitized
}

// SanitizeSanitizedError returns a durable-safe copy of error metadata.
// Missing or unsafe required error codes return the zero value.
func SanitizeSanitizedError(err SanitizedError) SanitizedError {
	sanitized := NormalizeSanitizedError(err)
	sanitized.Code = sanitizeErrorCodeValue(sanitized.Code)
	if sanitized.Code == "" {
		return SanitizedError{}
	}
	sanitized.Field = sanitizeFieldPath(sanitized.Field)
	sanitized.BindingID = sanitizeIdentifier(sanitized.BindingID)
	sanitized.Mode = sanitizeOptionalModeValue(sanitized.Mode)
	sanitized.ReasonCode = sanitizeReasonCodeValue(sanitized.ReasonCode)
	return sanitized
}

// SanitizeSanitizedErrorRecords returns durable-safe error records while
// preserving nil versus explicit empty input slices.
func SanitizeSanitizedErrorRecords(errors []SanitizedError) []SanitizedError {
	if errors == nil {
		return nil
	}
	sanitized := make([]SanitizedError, 0, len(errors))
	for _, err := range errors {
		record := SanitizeSanitizedError(err)
		if record.Code != "" {
			sanitized = append(sanitized, record)
		}
	}
	return sanitized
}

// SanitizeValidationResult returns a durable-safe copy of validation output.
func SanitizeValidationResult(result ValidationResult) ValidationResult {
	return ValidationResult{
		Valid:  result.Valid,
		Errors: SanitizeSanitizedErrorRecords(result.Errors),
	}
}

func sanitizeIdentifier(value string) string {
	if value == "" || unsafeCredentialDeliveryIdentifier(value) {
		return ""
	}
	return value
}

func sanitizeSecretReference(value string) string {
	if value == "" || unsafeCredentialDeliverySecretReference(value) {
		return ""
	}
	return value
}

func sanitizeFieldPath(value string) string {
	if value == "" || unsafeCredentialDeliveryFieldPath(value) {
		return ""
	}
	return value
}

func sanitizeLabelRecords(values []string) []string {
	if values == nil {
		return nil
	}
	sanitized := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || unsafeCredentialDeliveryLabel(value) {
			continue
		}
		sanitized = append(sanitized, value)
	}
	return sanitized
}

func sanitizeOptionalModeRecords(values []Mode) []Mode {
	if values == nil {
		return nil
	}
	sanitized := make([]Mode, 0, len(values))
	for _, value := range values {
		value = sanitizeOptionalModeValue(value)
		if value == "" {
			continue
		}
		sanitized = append(sanitized, value)
	}
	return sanitized
}

func sanitizeRequiredModeValue(mode Mode) Mode {
	mode = normalizeMode(mode)
	if mode == "" || unsafeCredentialDeliveryFreeformMetadata(string(mode)) || !validMode(mode) {
		return ""
	}
	return mode
}

func sanitizeOptionalModeValue(mode Mode) Mode {
	mode = normalizeMode(mode)
	if mode != "" && (unsafeCredentialDeliveryFreeformMetadata(string(mode)) || !validMode(mode)) {
		return ""
	}
	return mode
}

func sanitizeDestinationCategoryValue(category DestinationCategory) DestinationCategory {
	category = normalizeDestinationCategory(category)
	if category != "" && (unsafeCredentialDeliveryFreeformMetadata(string(category)) || !validDestinationCategory(category)) {
		return ""
	}
	return category
}

func sanitizeSourceValue(source Source) Source {
	source = normalizeSource(source)
	if source != "" && (unsafeCredentialDeliveryFreeformMetadata(string(source)) || !validSource(source)) {
		return ""
	}
	return source
}

func sanitizeStatusValue(status Status) Status {
	status = normalizeStatus(status)
	if status != "" && (unsafeCredentialDeliveryFreeformMetadata(string(status)) || !validStatus(status)) {
		return ""
	}
	return status
}

func sanitizeReasonCodeValue(reason ReasonCode) ReasonCode {
	reason = normalizeReasonCode(reason)
	if reason != "" && (unsafeCredentialDeliveryFreeformMetadata(string(reason)) || !validReasonCode(reason)) {
		return ""
	}
	return reason
}

func sanitizeWarningCodeValue(warning WarningCode) WarningCode {
	warning = normalizeWarningCode(warning)
	if warning == "" || unsafeCredentialDeliveryFreeformMetadata(string(warning)) || !validWarningCode(warning) {
		return ""
	}
	return warning
}

func sanitizeErrorCodeValue(code ErrorCode) ErrorCode {
	code = normalizeErrorCode(code)
	if code == "" || unsafeCredentialDeliveryFreeformMetadata(string(code)) || !validErrorCode(code) {
		return ""
	}
	return code
}
