package sandbox

import (
	"strings"
)

// SandboxSecurityCapabilityReadinessValidationCode identifies a sanitized
// readiness validation failure without carrying rejected input values.
type SandboxSecurityCapabilityReadinessValidationCode string

const (
	SandboxSecurityCapabilityReadinessValidationMissingRequiredField SandboxSecurityCapabilityReadinessValidationCode = "missing_required_field"
	SandboxSecurityCapabilityReadinessValidationInvalidEnum          SandboxSecurityCapabilityReadinessValidationCode = "invalid_enum"
	SandboxSecurityCapabilityReadinessValidationUnsafeMetadata       SandboxSecurityCapabilityReadinessValidationCode = "unsafe_metadata"
)

// SandboxSecurityCapabilityReadinessValidationError identifies unsafe or
// invalid readiness metadata by safe field path only.
type SandboxSecurityCapabilityReadinessValidationError struct {
	Code    SandboxSecurityCapabilityReadinessValidationCode `json:"code"`
	Field   string                                           `json:"field,omitempty"`
	Message string                                           `json:"message,omitempty"`
}

// Error returns a redaction-safe error string for callers that surface
// validation entries as ordinary errors.
func (e SandboxSecurityCapabilityReadinessValidationError) Error() string {
	var b strings.Builder
	b.WriteString("security capability readiness validation error")
	if e.Code != "" {
		b.WriteString(": code=")
		b.WriteString(string(e.Code))
	}
	if e.Field != "" {
		b.WriteString(" field=")
		b.WriteString(e.Field)
	}
	if e.Message != "" {
		b.WriteString(" message=")
		b.WriteString(e.Message)
	}
	return b.String()
}

// SandboxSecurityCapabilityReadinessValidationResult is the deterministic
// output of pure readiness input validation.
type SandboxSecurityCapabilityReadinessValidationResult struct {
	Valid      bool                                                `json:"valid"`
	Normalized *SandboxSecurityCapabilityReadinessInput            `json:"normalized,omitempty"`
	Errors     []SandboxSecurityCapabilityReadinessValidationError `json:"errors,omitempty"`
}

// ValidateAndNormalizeSandboxSecurityCapabilityReadinessInput validates
// readiness metadata using only enum-like labels and safe identifiers.
func ValidateAndNormalizeSandboxSecurityCapabilityReadinessInput(input SandboxSecurityCapabilityReadinessInput) SandboxSecurityCapabilityReadinessValidationResult {
	result := SandboxSecurityCapabilityReadinessValidationResult{Valid: true}

	for i, metadata := range input.Requested {
		validateSandboxSecurityCapabilityMetadata(&result, "requested", i, metadata, true)
	}
	for i, metadata := range input.Ready {
		validateSandboxSecurityCapabilityMetadata(&result, "ready", i, metadata, false)
	}
	for i, posture := range input.WorkerPostures {
		validateSandboxSecurityCapabilityWorkerPosture(&result, i, posture)
	}
	validateSandboxSecurityCapabilityNetworkProxyInput(&result, input.NetworkProxySession)
	validateSandboxSecurityCapabilityDecisionLogsInput(&result, input.NetworkPolicyDecisionLogs)
	validateSandboxSecurityCapabilityCredentialProxyInput(&result, input)

	if len(result.Errors) > 0 {
		result.Valid = false
		return result
	}
	normalized := SanitizeSandboxSecurityCapabilityReadinessInput(input)
	result.Normalized = &normalized
	return result
}

// SanitizeSandboxSecurityCapabilityReadinessInput returns a durable-safe copy
// of readiness input. Unsafe records are omitted instead of redacted.
func SanitizeSandboxSecurityCapabilityReadinessInput(input SandboxSecurityCapabilityReadinessInput) SandboxSecurityCapabilityReadinessInput {
	return SandboxSecurityCapabilityReadinessInput{
		Requested:                 sanitizeSandboxSecurityCapabilityMetadataRecords(input.Requested, true),
		Ready:                     sanitizeSandboxSecurityCapabilityMetadataRecords(input.Ready, false),
		WorkerPostures:            sanitizeSandboxSecurityCapabilityWorkerPostures(input.WorkerPostures),
		NetworkProxySession:       sanitizeSandboxSecurityCapabilityNetworkProxySession(input.NetworkProxySession),
		NetworkPolicyDecisionLogs: sanitizeSandboxSecurityCapabilityNetworkPolicyDecisionLogs(input.NetworkPolicyDecisionLogs),
		CredentialProxyPlan:       sanitizeSandboxSecurityCapabilityCredentialProxyPlan(input.CredentialProxyPlan),
		CredentialProxySession:    sanitizeSandboxSecurityCapabilityCredentialProxySession(input.CredentialProxySession),
		CredentialProxyBindings:   SanitizeSandboxCredentialProxyBindingMetadataRecords(input.CredentialProxyBindings),
	}
}

// SanitizeSandboxSecurityCapabilityReadinessOutput returns a durable-safe copy
// of readiness output. Unsafe result records are omitted instead of redacted.
func SanitizeSandboxSecurityCapabilityReadinessOutput(output SandboxSecurityCapabilityReadinessOutput) SandboxSecurityCapabilityReadinessOutput {
	if len(output.Results) == 0 {
		return SandboxSecurityCapabilityReadinessOutput{}
	}
	results := make([]SandboxSecurityCapabilityReadinessResult, 0, len(output.Results))
	for _, result := range output.Results {
		sanitized, ok := sanitizeSandboxSecurityCapabilityReadinessResult(result)
		if ok {
			results = append(results, sanitized)
		}
	}
	return SandboxSecurityCapabilityReadinessOutput{Results: results}
}

func sanitizeSandboxSecurityCapabilityMetadataRecords(records []SandboxSecurityCapabilityMetadata, requested bool) []SandboxSecurityCapabilityMetadata {
	if len(records) == 0 {
		return nil
	}
	sanitized := make([]SandboxSecurityCapabilityMetadata, 0, len(records))
	for _, record := range records {
		metadata, ok := sanitizeSandboxSecurityCapabilityInputMetadata(record, requested)
		if ok {
			sanitized = append(sanitized, metadata)
		}
	}
	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
}

func sanitizeSandboxSecurityCapabilityInputMetadata(metadata SandboxSecurityCapabilityMetadata, requested bool) (SandboxSecurityCapabilityMetadata, bool) {
	normalized := normalizeSandboxSecurityCapabilityMetadata(metadata)
	if !sandboxSecurityCapabilityKnownFamily(normalized.Family) || !sandboxSecurityCapabilityKnownCapability(normalized.Capability) {
		return SandboxSecurityCapabilityMetadata{}, false
	}
	if normalized.Mode != "" {
		normalized.Mode = sandboxSecurityCapabilitySafeMode(normalized.Family, normalized.Capability, normalized.Mode)
		if normalized.Mode == "" {
			return SandboxSecurityCapabilityMetadata{}, false
		}
	}
	normalized.ID = sanitizeSandboxSecurityCapabilityIdentifier(normalized.ID)
	normalized.Source = sanitizeSandboxSecurityCapabilitySourceValue(normalized.Source)
	normalized.WarningCodes = sanitizeSandboxSecurityCapabilityWarningCodes(normalized.WarningCodes)

	if requested {
		normalized.Status = ""
		normalized.ReasonCode = ""
		return normalized, true
	}
	if normalized.Status != "" {
		normalized.Status = sanitizeSandboxSecurityCapabilityReadinessStateValue(normalized.Status)
		if normalized.Status == "" {
			return SandboxSecurityCapabilityMetadata{}, false
		}
	}
	if normalized.ReasonCode != "" {
		normalized.ReasonCode = sanitizeSandboxSecurityCapabilityReasonCodeValue(normalized.ReasonCode)
		if normalized.ReasonCode == "" {
			return SandboxSecurityCapabilityMetadata{}, false
		}
	}
	return normalized, true
}

func sanitizeSandboxSecurityCapabilityWorkerPostures(postures []SandboxSecurityCapabilityWorkerPostureMetadata) []SandboxSecurityCapabilityWorkerPostureMetadata {
	if len(postures) == 0 {
		return nil
	}
	sanitized := make([]SandboxSecurityCapabilityWorkerPostureMetadata, 0, len(postures))
	for _, posture := range postures {
		record := SandboxSecurityCapabilityWorkerPostureMetadata{
			WorkerKind:          sanitizeSandboxSecurityCapabilityWorkerKindValue(posture.WorkerKind),
			RuntimeDriver:       sanitizeSandboxSecurityCapabilityRuntimeDriverValue(posture.RuntimeDriver),
			IsolationLevel:      sanitizeSandboxSecurityCapabilityIsolationLevelValue(posture.IsolationLevel),
			NetworkPolicy:       sanitizeSandboxSecurityCapabilityNetworkPolicyValue(posture.NetworkPolicy),
			NetworkEnforcement:  sanitizeSandboxSecurityCapabilityNetworkEnforcementValue(posture.NetworkEnforcement),
			CredentialModes:     sanitizeSandboxSecurityCapabilitySecretModes(posture.CredentialModes),
			CredentialProxyMode: posture.CredentialProxyMode,
		}
		if record.WorkerKind == "" &&
			record.RuntimeDriver == "" &&
			record.IsolationLevel == "" &&
			record.NetworkPolicy == "" &&
			record.NetworkEnforcement == "" &&
			len(record.CredentialModes) == 0 &&
			!record.CredentialProxyMode {
			continue
		}
		sanitized = append(sanitized, record)
	}
	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
}

func sanitizeSandboxSecurityCapabilityNetworkProxySession(session *SandboxNetworkProxySessionMetadata) *SandboxNetworkProxySessionMetadata {
	if session == nil {
		return nil
	}
	validation := ValidateAndNormalizeSandboxNetworkProxySessionMetadata(*session)
	if !validation.Valid || validation.Normalized == nil {
		return nil
	}
	sanitized := SanitizeSandboxNetworkProxySessionMetadata(*validation.Normalized)
	if sanitized.ID == "" || sanitized.Source == "" {
		return nil
	}
	return &sanitized
}

func sanitizeSandboxSecurityCapabilityNetworkPolicyDecisionLogs(records []SandboxNetworkPolicyDecisionLogRecord) []SandboxNetworkPolicyDecisionLogRecord {
	if len(records) == 0 {
		return nil
	}
	sanitized := make([]SandboxNetworkPolicyDecisionLogRecord, 0, len(records))
	for _, record := range records {
		validation := ValidateAndNormalizeSandboxNetworkPolicyDecisionLogRecord(record)
		if !validation.Valid || len(validation.Normalized) == 0 {
			continue
		}
		sanitized = append(sanitized, SanitizeSandboxNetworkPolicyDecisionLogRecord(validation.Normalized[0]))
	}
	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
}

func sanitizeSandboxSecurityCapabilityCredentialProxyPlan(plan *SandboxCredentialProxyPlanMetadata) *SandboxCredentialProxyPlanMetadata {
	if plan == nil {
		return nil
	}
	normalized := NormalizeSandboxCredentialProxyPlanMetadata(*plan)
	if validation := ValidateSandboxCredentialProxyPlanMetadata(normalized); !validation.Valid {
		return nil
	}
	sanitized := SanitizeSandboxCredentialProxyPlanMetadata(normalized)
	if sanitized.ID == "" {
		return nil
	}
	return &sanitized
}

func sanitizeSandboxSecurityCapabilityCredentialProxySession(session *SandboxCredentialProxySessionMetadata) *SandboxCredentialProxySessionMetadata {
	if session == nil {
		return nil
	}
	normalized := NormalizeSandboxCredentialProxySessionMetadata(*session)
	if validation := ValidateSandboxCredentialProxySessionMetadata(normalized); !validation.Valid {
		return nil
	}
	sanitized := SanitizeSandboxCredentialProxySessionMetadata(normalized)
	if sanitized.ID == "" {
		return nil
	}
	return &sanitized
}

func sanitizeSandboxSecurityCapabilityReadinessResult(result SandboxSecurityCapabilityReadinessResult) (SandboxSecurityCapabilityReadinessResult, bool) {
	sanitized := SandboxSecurityCapabilityReadinessResult{
		State:        sanitizeSandboxSecurityCapabilityReadinessStateValue(result.State),
		ReasonCode:   sanitizeSandboxSecurityCapabilityReasonCodeValue(result.ReasonCode),
		WarningCodes: sanitizeSandboxSecurityCapabilityWarningCodes(result.WarningCodes),
	}
	if sanitized.State == "" {
		return SandboxSecurityCapabilityReadinessResult{}, false
	}
	if result.Metadata != nil {
		if metadata, ok := sanitizeSandboxSecurityCapabilityResultMetadata(*result.Metadata); ok {
			sanitized.Metadata = &metadata
		}
	}
	if result.Requested != nil {
		if requested, ok := sanitizeSandboxSecurityCapabilityResultMetadata(*result.Requested); ok {
			sanitized.Requested = &requested
		}
	}
	if result.Ready != nil {
		if ready, ok := sanitizeSandboxSecurityCapabilityResultMetadata(*result.Ready); ok {
			sanitized.Ready = &ready
		}
	}
	return sanitized, true
}

func sanitizeSandboxSecurityCapabilityResultMetadata(metadata SandboxSecurityCapabilityMetadata) (SandboxSecurityCapabilityMetadata, bool) {
	normalized := normalizeSandboxSecurityCapabilityMetadata(metadata)
	if !sandboxSecurityCapabilityKnownFamily(normalized.Family) || !sandboxSecurityCapabilityKnownCapability(normalized.Capability) {
		return SandboxSecurityCapabilityMetadata{}, false
	}
	if normalized.Mode != "" {
		normalized.Mode = sandboxSecurityCapabilitySafeMode(normalized.Family, normalized.Capability, normalized.Mode)
		if normalized.Mode == "" {
			return SandboxSecurityCapabilityMetadata{}, false
		}
	}
	normalized.ID = sanitizeSandboxSecurityCapabilityIdentifier(normalized.ID)
	normalized.Source = sanitizeSandboxSecurityCapabilitySourceValue(normalized.Source)
	normalized.Status = sanitizeSandboxSecurityCapabilityReadinessStateValue(normalized.Status)
	normalized.ReasonCode = sanitizeSandboxSecurityCapabilityReasonCodeValue(normalized.ReasonCode)
	normalized.WarningCodes = sanitizeSandboxSecurityCapabilityWarningCodes(normalized.WarningCodes)
	return normalized, true
}

func normalizeSandboxSecurityCapabilityMetadata(metadata SandboxSecurityCapabilityMetadata) SandboxSecurityCapabilityMetadata {
	return SandboxSecurityCapabilityMetadata{
		ID:           strings.TrimSpace(metadata.ID),
		Family:       normalizeSandboxSecurityCapabilityFamily(metadata.Family),
		Capability:   normalizeSandboxSecurityCapabilityName(metadata.Capability),
		Mode:         strings.ToLower(strings.TrimSpace(metadata.Mode)),
		Source:       normalizeSandboxSecurityCapabilitySource(metadata.Source),
		Status:       normalizeSandboxSecurityCapabilityReadinessState(metadata.Status),
		ReasonCode:   normalizeSandboxSecurityCapabilityReasonCode(metadata.ReasonCode),
		WarningCodes: normalizeSandboxSecurityCapabilityWarningCodes(metadata.WarningCodes),
	}
}

func normalizeSandboxSecurityCapabilityWarningCodes(warnings []SandboxSecurityCapabilityWarningCode) []SandboxSecurityCapabilityWarningCode {
	if len(warnings) == 0 {
		return nil
	}
	normalized := make([]SandboxSecurityCapabilityWarningCode, 0, len(warnings))
	for _, warning := range warnings {
		normalized = append(normalized, normalizeSandboxSecurityCapabilityWarningCode(warning))
	}
	return normalized
}

func sanitizeSandboxSecurityCapabilityWarningCodes(warnings []SandboxSecurityCapabilityWarningCode) []SandboxSecurityCapabilityWarningCode {
	if len(warnings) == 0 {
		return nil
	}
	sanitized := make([]SandboxSecurityCapabilityWarningCode, 0, len(warnings))
	for _, warning := range warnings {
		warning = sanitizeSandboxSecurityCapabilityWarningCodeValue(warning)
		if warning != "" {
			sanitized = append(sanitized, warning)
		}
	}
	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
}

func sanitizeSandboxSecurityCapabilitySecretModes(modes []string) []string {
	if len(modes) == 0 {
		return nil
	}
	sanitized := make([]string, 0, len(modes))
	for _, mode := range modes {
		mode = sandboxSecurityCapabilitySafeSecretMode(strings.ToLower(strings.TrimSpace(mode)))
		if mode == "" {
			continue
		}
		duplicate := false
		for _, existing := range sanitized {
			if existing == mode {
				duplicate = true
				break
			}
		}
		if !duplicate {
			sanitized = append(sanitized, mode)
		}
	}
	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
}

func sanitizeSandboxSecurityCapabilityIdentifier(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || unsafeSandboxCredentialProxyIdentifier(value) {
		return ""
	}
	return value
}

func sanitizeSandboxSecurityCapabilitySourceValue(source SandboxSecurityCapabilitySource) SandboxSecurityCapabilitySource {
	source = normalizeSandboxSecurityCapabilitySource(source)
	if !sandboxSecurityCapabilityKnownSource(source) {
		return ""
	}
	return source
}

func sanitizeSandboxSecurityCapabilityReadinessStateValue(state SandboxSecurityCapabilityReadinessState) SandboxSecurityCapabilityReadinessState {
	state = normalizeSandboxSecurityCapabilityReadinessState(state)
	if state != "" && !sandboxSecurityCapabilityKnownReadinessState(state) {
		return ""
	}
	return state
}

func sanitizeSandboxSecurityCapabilityReasonCodeValue(reason SandboxSecurityCapabilityReasonCode) SandboxSecurityCapabilityReasonCode {
	reason = normalizeSandboxSecurityCapabilityReasonCode(reason)
	if reason != "" && !sandboxSecurityCapabilityKnownReasonCode(reason) {
		return ""
	}
	return reason
}

func sanitizeSandboxSecurityCapabilityWarningCodeValue(warning SandboxSecurityCapabilityWarningCode) SandboxSecurityCapabilityWarningCode {
	warning = normalizeSandboxSecurityCapabilityWarningCode(warning)
	if warning != "" && !sandboxSecurityCapabilityKnownWarningCode(warning) {
		return ""
	}
	return warning
}

func sanitizeSandboxSecurityCapabilityWorkerKindValue(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case SandboxHostKindLocal, SandboxHostKindSSH, SandboxHostKindWorker, SandboxHostKindK8s:
		return value
	default:
		return ""
	}
}

func sanitizeSandboxSecurityCapabilityRuntimeDriverValue(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case SandboxRuntimeDriverSSHMachine, SandboxRuntimeDriverRootlessPodman, SandboxRuntimeDriverMicroVM:
		return value
	default:
		return ""
	}
}

func sanitizeSandboxSecurityCapabilityIsolationLevelValue(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case SandboxIsolationLevelHost, SandboxIsolationLevelContainer, SandboxIsolationLevelVM:
		return value
	default:
		return ""
	}
}

func sanitizeSandboxSecurityCapabilityNetworkPolicyValue(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case SandboxNetworkPolicyDenyByDefault, SandboxNetworkPolicyBestEffort:
		return value
	default:
		return ""
	}
}

func sanitizeSandboxSecurityCapabilityNetworkEnforcementValue(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case SandboxNetworkEnforcementModeNone,
		SandboxNetworkEnforcementModeBestEffort,
		SandboxNetworkEnforcementModeProxy,
		SandboxNetworkEnforcementModeFirewall,
		SandboxNetworkEnforcementModeRuntime,
		SandboxNetworkEnforcementModeProxyFirewall:
		return value
	default:
		return ""
	}
}

func normalizeSandboxSecurityCapabilityFamily(family SandboxSecurityCapabilityFamily) SandboxSecurityCapabilityFamily {
	return SandboxSecurityCapabilityFamily(strings.ToLower(strings.TrimSpace(string(family))))
}

func normalizeSandboxSecurityCapabilityName(capability SandboxSecurityCapabilityName) SandboxSecurityCapabilityName {
	return SandboxSecurityCapabilityName(strings.ToLower(strings.TrimSpace(string(capability))))
}

func normalizeSandboxSecurityCapabilitySource(source SandboxSecurityCapabilitySource) SandboxSecurityCapabilitySource {
	return SandboxSecurityCapabilitySource(strings.ToLower(strings.TrimSpace(string(source))))
}

func normalizeSandboxSecurityCapabilityReadinessState(state SandboxSecurityCapabilityReadinessState) SandboxSecurityCapabilityReadinessState {
	return SandboxSecurityCapabilityReadinessState(strings.ToLower(strings.TrimSpace(string(state))))
}

func normalizeSandboxSecurityCapabilityReasonCode(reason SandboxSecurityCapabilityReasonCode) SandboxSecurityCapabilityReasonCode {
	return SandboxSecurityCapabilityReasonCode(strings.ToLower(strings.TrimSpace(string(reason))))
}

func normalizeSandboxSecurityCapabilityWarningCode(warning SandboxSecurityCapabilityWarningCode) SandboxSecurityCapabilityWarningCode {
	return SandboxSecurityCapabilityWarningCode(strings.ToLower(strings.TrimSpace(string(warning))))
}

func validateSandboxSecurityCapabilityMetadata(result *SandboxSecurityCapabilityReadinessValidationResult, collection string, index int, metadata SandboxSecurityCapabilityMetadata, requested bool) {
	normalized := normalizeSandboxSecurityCapabilityMetadata(metadata)
	prefix := collection + "."
	if normalized.ID != "" && sanitizeSandboxSecurityCapabilityIdentifier(metadata.ID) == "" {
		result.addError(index, prefix+"id", SandboxSecurityCapabilityReadinessValidationUnsafeMetadata, "readiness metadata id must be a safe identifier")
	}
	if normalized.Family == "" {
		result.addError(index, prefix+"family", SandboxSecurityCapabilityReadinessValidationMissingRequiredField, "readiness capability family is required")
	} else if unsafeSandboxSecurityCapabilityFreeformMetadata(string(metadata.Family)) {
		result.addError(index, prefix+"family", SandboxSecurityCapabilityReadinessValidationUnsafeMetadata, "readiness capability family is unsafe")
	} else if !sandboxSecurityCapabilityKnownFamily(normalized.Family) {
		result.addError(index, prefix+"family", SandboxSecurityCapabilityReadinessValidationInvalidEnum, "readiness capability family is unsupported")
	}
	if normalized.Capability == "" {
		result.addError(index, prefix+"capability", SandboxSecurityCapabilityReadinessValidationMissingRequiredField, "readiness capability name is required")
	} else if unsafeSandboxSecurityCapabilityFreeformMetadata(string(metadata.Capability)) {
		result.addError(index, prefix+"capability", SandboxSecurityCapabilityReadinessValidationUnsafeMetadata, "readiness capability name is unsafe")
	} else if !sandboxSecurityCapabilityKnownCapability(normalized.Capability) {
		result.addError(index, prefix+"capability", SandboxSecurityCapabilityReadinessValidationInvalidEnum, "readiness capability name is unsupported")
	}
	if normalized.Mode != "" && sandboxSecurityCapabilitySafeMode(normalized.Family, normalized.Capability, normalized.Mode) == "" {
		code := SandboxSecurityCapabilityReadinessValidationInvalidEnum
		if unsafeSandboxSecurityCapabilityFreeformMetadata(metadata.Mode) {
			code = SandboxSecurityCapabilityReadinessValidationUnsafeMetadata
		}
		result.addError(index, prefix+"mode", code, "readiness capability mode is unsupported")
	}
	if metadata.Source != "" {
		validateSandboxSecurityCapabilityEnum(result, index, prefix+"source", string(metadata.Source), sandboxSecurityCapabilityKnownSourceString, "readiness capability source is unsupported")
	}
	if !requested && metadata.Status != "" {
		validateSandboxSecurityCapabilityEnum(result, index, prefix+"status", string(metadata.Status), sandboxSecurityCapabilityKnownReadinessStateString, "readiness capability status is unsupported")
	}
	if !requested && metadata.ReasonCode != "" {
		validateSandboxSecurityCapabilityEnum(result, index, prefix+"reasonCode", string(metadata.ReasonCode), sandboxSecurityCapabilityKnownReasonCodeString, "readiness capability reason code is unsupported")
	}
	for i, warning := range metadata.WarningCodes {
		field := prefix + "warningCodes[" + sandboxSecurityCapabilityIndexString(i) + "]"
		validateSandboxSecurityCapabilityEnum(result, index, field, string(warning), sandboxSecurityCapabilityKnownWarningCodeString, "readiness capability warning code is unsupported")
	}
}

func validateSandboxSecurityCapabilityWorkerPosture(result *SandboxSecurityCapabilityReadinessValidationResult, index int, posture SandboxSecurityCapabilityWorkerPostureMetadata) {
	validateSandboxSecurityCapabilityLabel(result, index, "workerPostures.workerKind", posture.WorkerKind, sanitizeSandboxSecurityCapabilityWorkerKindValue, "worker posture kind is unsupported")
	validateSandboxSecurityCapabilityLabel(result, index, "workerPostures.runtimeDriver", posture.RuntimeDriver, sanitizeSandboxSecurityCapabilityRuntimeDriverValue, "worker posture runtime driver is unsupported")
	validateSandboxSecurityCapabilityLabel(result, index, "workerPostures.isolationLevel", posture.IsolationLevel, sanitizeSandboxSecurityCapabilityIsolationLevelValue, "worker posture isolation level is unsupported")
	validateSandboxSecurityCapabilityLabel(result, index, "workerPostures.networkPolicy", posture.NetworkPolicy, sanitizeSandboxSecurityCapabilityNetworkPolicyValue, "worker posture network policy is unsupported")
	validateSandboxSecurityCapabilityLabel(result, index, "workerPostures.networkEnforcement", posture.NetworkEnforcement, sanitizeSandboxSecurityCapabilityNetworkEnforcementValue, "worker posture network enforcement is unsupported")
	for i, mode := range posture.CredentialModes {
		field := "workerPostures.credentialModes[" + sandboxSecurityCapabilityIndexString(i) + "]"
		validateSandboxSecurityCapabilityLabel(result, index, field, mode, func(value string) string {
			return sandboxSecurityCapabilitySafeSecretMode(strings.ToLower(strings.TrimSpace(value)))
		}, "worker posture credential mode is unsupported")
	}
}

func validateSandboxSecurityCapabilityNetworkProxyInput(result *SandboxSecurityCapabilityReadinessValidationResult, session *SandboxNetworkProxySessionMetadata) {
	if session == nil {
		return
	}
	validation := ValidateAndNormalizeSandboxNetworkProxySessionMetadata(*session)
	for _, err := range validation.Errors {
		result.addError(nilRecordIndex, "networkProxySession."+err.Field, SandboxSecurityCapabilityReadinessValidationUnsafeMetadata, err.Message)
	}
}

func validateSandboxSecurityCapabilityDecisionLogsInput(result *SandboxSecurityCapabilityReadinessValidationResult, records []SandboxNetworkPolicyDecisionLogRecord) {
	validation := ValidateAndNormalizeSandboxNetworkPolicyDecisionLogRecords(records)
	for _, err := range validation.Errors {
		result.addError(err.RecordIndex, "networkPolicyDecisionLogs."+err.Field, SandboxSecurityCapabilityReadinessValidationUnsafeMetadata, err.Message)
	}
}

func validateSandboxSecurityCapabilityCredentialProxyInput(result *SandboxSecurityCapabilityReadinessValidationResult, input SandboxSecurityCapabilityReadinessInput) {
	if input.CredentialProxyPlan != nil {
		normalized := NormalizeSandboxCredentialProxyPlanMetadata(*input.CredentialProxyPlan)
		for _, err := range ValidateSandboxCredentialProxyPlanMetadata(normalized).Errors {
			result.addError(nilRecordIndex, "credentialPlanMetadata."+err.Field, SandboxSecurityCapabilityReadinessValidationUnsafeMetadata, err.Message)
		}
	}
	if input.CredentialProxySession != nil {
		normalized := NormalizeSandboxCredentialProxySessionMetadata(*input.CredentialProxySession)
		for _, err := range ValidateSandboxCredentialProxySessionMetadata(normalized).Errors {
			result.addError(nilRecordIndex, "credentialSessionMetadata."+err.Field, SandboxSecurityCapabilityReadinessValidationUnsafeMetadata, err.Message)
		}
	}
	for i, binding := range input.CredentialProxyBindings {
		normalized := NormalizeSandboxCredentialProxyBindingMetadata(binding)
		for _, err := range ValidateSandboxCredentialProxyBindingMetadata(normalized).Errors {
			result.addError(i, "credentialBindingMetadata."+err.Field, SandboxSecurityCapabilityReadinessValidationUnsafeMetadata, err.Message)
		}
	}
}

type sandboxSecurityCapabilityLabelSanitizer func(string) string

func validateSandboxSecurityCapabilityLabel(result *SandboxSecurityCapabilityReadinessValidationResult, index int, field, value string, sanitize sandboxSecurityCapabilityLabelSanitizer, message string) {
	if value == "" {
		return
	}
	if unsafeSandboxSecurityCapabilityFreeformMetadata(value) {
		result.addError(index, field, SandboxSecurityCapabilityReadinessValidationUnsafeMetadata, message)
		return
	}
	if sanitize(value) == "" {
		result.addError(index, field, SandboxSecurityCapabilityReadinessValidationInvalidEnum, message)
	}
}

type sandboxSecurityCapabilityEnumValidator func(string) bool

func validateSandboxSecurityCapabilityEnum(result *SandboxSecurityCapabilityReadinessValidationResult, index int, field, value string, valid sandboxSecurityCapabilityEnumValidator, message string) {
	if unsafeSandboxSecurityCapabilityFreeformMetadata(value) {
		result.addError(index, field, SandboxSecurityCapabilityReadinessValidationUnsafeMetadata, message)
		return
	}
	if !valid(strings.ToLower(strings.TrimSpace(value))) {
		result.addError(index, field, SandboxSecurityCapabilityReadinessValidationInvalidEnum, message)
	}
}

const nilRecordIndex = -1

func (r *SandboxSecurityCapabilityReadinessValidationResult) addError(recordIndex int, field string, code SandboxSecurityCapabilityReadinessValidationCode, message string) {
	r.Errors = append(r.Errors, SandboxSecurityCapabilityReadinessValidationError{
		Code:    code,
		Field:   sandboxSecurityCapabilityIndexedField(field, recordIndex),
		Message: message,
	})
}

func sandboxSecurityCapabilityIndexedField(field string, index int) string {
	if index < 0 {
		return field
	}
	if dot := strings.IndexByte(field, '.'); dot >= 0 {
		return field[:dot] + "[" + sandboxSecurityCapabilityIndexString(index) + "]" + field[dot:]
	}
	return field + "[" + sandboxSecurityCapabilityIndexString(index) + "]"
}

func sandboxSecurityCapabilityIndexString(index int) string {
	if index == 0 {
		return "0"
	}
	var digits [20]byte
	i := len(digits)
	for index > 0 {
		i--
		digits[i] = byte('0' + index%10)
		index /= 10
	}
	return string(digits[i:])
}

func unsafeSandboxSecurityCapabilityFreeformMetadata(value string) bool {
	return unsafeSandboxCredentialProxyFreeformMetadata(value)
}

func sandboxSecurityCapabilityKnownSource(source SandboxSecurityCapabilitySource) bool {
	switch source {
	case SandboxSecurityCapabilitySourceRequested,
		SandboxSecurityCapabilitySourceMetadata,
		SandboxSecurityCapabilitySourceRuntime,
		SandboxSecurityCapabilitySourceWorker:
		return true
	default:
		return false
	}
}

func sandboxSecurityCapabilityKnownReadinessState(state SandboxSecurityCapabilityReadinessState) bool {
	switch state {
	case SandboxSecurityCapabilityReadinessMetadataOnly,
		SandboxSecurityCapabilityReadinessUnsupported,
		SandboxSecurityCapabilityReadinessBlocked,
		SandboxSecurityCapabilityReadinessReady:
		return true
	default:
		return false
	}
}

func sandboxSecurityCapabilityKnownReasonCode(reason SandboxSecurityCapabilityReasonCode) bool {
	switch reason {
	case SandboxSecurityCapabilityReasonMetadataOnly,
		SandboxSecurityCapabilityReasonCapabilityMissing,
		SandboxSecurityCapabilityReasonModeUnsupported,
		SandboxSecurityCapabilityReasonCapabilityBlocked,
		SandboxSecurityCapabilityReasonCapabilityConfirmed,
		SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
		SandboxSecurityCapabilityReasonMetadataDeliveryUnproven,
		SandboxSecurityCapabilityReasonUnknown:
		return true
	default:
		return false
	}
}

func sandboxSecurityCapabilityKnownWarningCode(warning SandboxSecurityCapabilityWarningCode) bool {
	switch warning {
	case SandboxSecurityCapabilityWarningMetadataNotCapability,
		SandboxSecurityCapabilityWarningUnsupportedMode,
		SandboxSecurityCapabilityWarningBlockedByPolicy:
		return true
	default:
		return false
	}
}

func sandboxSecurityCapabilityKnownSourceString(value string) bool {
	return sandboxSecurityCapabilityKnownSource(SandboxSecurityCapabilitySource(value))
}

func sandboxSecurityCapabilityKnownReadinessStateString(value string) bool {
	return sandboxSecurityCapabilityKnownReadinessState(SandboxSecurityCapabilityReadinessState(value))
}

func sandboxSecurityCapabilityKnownReasonCodeString(value string) bool {
	return sandboxSecurityCapabilityKnownReasonCode(SandboxSecurityCapabilityReasonCode(value))
}

func sandboxSecurityCapabilityKnownWarningCodeString(value string) bool {
	return sandboxSecurityCapabilityKnownWarningCode(SandboxSecurityCapabilityWarningCode(value))
}
