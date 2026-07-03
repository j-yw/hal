package credentialdelivery

import (
	"encoding/json"
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
)

// ActivationAdapter is the narrow boundary for credential delivery activation.
// Implementations receive only sanitized metadata and must return only
// redaction-safe activation metadata.
type ActivationAdapter interface {
	ActivateCredentialDelivery(SanitizedActivationRequest) (ActivationResult, error)
}

// SanitizedActivationRequest wraps adapter input so injected adapters cannot
// observe unsanitized plan or binding metadata.
type SanitizedActivationRequest struct {
	request ActivationRequest
}

// NewSanitizedActivationRequest returns a durable-safe activation input.
func NewSanitizedActivationRequest(request ActivationRequest) SanitizedActivationRequest {
	return SanitizedActivationRequest{request: SanitizeActivationRequestMetadata(request)}
}

// Request returns a sanitized copy of the adapter input.
func (r SanitizedActivationRequest) Request() ActivationRequest {
	return SanitizeActivationRequestMetadata(r.request)
}

// Plan returns a sanitized copy of the activation plan metadata.
func (r SanitizedActivationRequest) Plan() Plan {
	return r.Request().Plan
}

// Bindings returns sanitized binding metadata available to the adapter.
func (r SanitizedActivationRequest) Bindings() []Binding {
	return r.Request().Bindings
}

// MarshalJSON keeps adapter input safe if tests or diagnostics serialize it.
func (r SanitizedActivationRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.Request())
}

// SanitizeActivationRequestMetadata returns a safe activation adapter input.
// Missing or unsafe plan IDs return the zero value so callers can fail closed.
func SanitizeActivationRequestMetadata(request ActivationRequest) ActivationRequest {
	normalized := NormalizeActivationRequestMetadata(request)
	plan := SanitizePlanMetadata(normalized.Plan)
	if plan.ID == "" {
		return ActivationRequest{}
	}
	activationID := sanitizeIdentifier(normalized.ActivationID)
	if activationID == "" {
		activationID = defaultActivationID(plan.ID)
	}
	if activationID == "" {
		return ActivationRequest{}
	}
	return ActivationRequest{
		ActivationID: activationID,
		Plan:         plan,
		Bindings:     SanitizeBindingMetadataRecords(normalized.Bindings),
	}
}

// NormalizeActivationRequestMetadata returns a deterministic activation input
// copy before validation or persistence.
func NormalizeActivationRequestMetadata(request ActivationRequest) ActivationRequest {
	return ActivationRequest{
		ActivationID: normalizeActivationIdentifier(request.ActivationID),
		Plan:         NormalizePlanMetadata(request.Plan),
		Bindings:     NormalizeBindingMetadataRecords(request.Bindings),
	}
}

// ActivateDelivery sanitizes activation input and output. Without an injected
// adapter the result is planning-only and contains no active delivery modes.
func ActivateDelivery(request ActivationRequest, adapter ActivationAdapter) ActivationResult {
	modeErrors := activationModeMetadataErrors(request)
	sanitizedInput := NewSanitizedActivationRequest(request)
	input := sanitizedInput.Request()
	if input.ActivationID == "" || input.Plan.ID == "" {
		return ActivationResult{}
	}
	if len(modeErrors) > 0 {
		return activationModeMetadataFailedActivationResult(input, modeErrors)
	}
	if input.Plan.Status == StatusFailed || len(input.Plan.Errors) > 0 {
		return planFailedActivationResult(input)
	}
	if adapter == nil {
		return adapterUnavailableActivationResult(input)
	}

	result, err := adapter.ActivateCredentialDelivery(sanitizedInput)
	if err != nil {
		return adapterFailedActivationResult(input)
	}
	return finalizeAdapterActivationResult(input, result)
}

func normalizeActivationIdentifier(value string) string {
	return strings.TrimSpace(value)
}

func defaultActivationID(planID string) string {
	if planID == "" {
		return ""
	}
	return sanitizeIdentifier(planID + "-activation")
}

func adapterUnavailableActivationResult(input ActivationRequest) ActivationResult {
	return SanitizeActivationResultMetadata(ActivationResult{
		ID:             input.ActivationID,
		PlanID:         input.Plan.ID,
		RequestedModes: input.Plan.RequestedModes,
		Bindings:       activationBindingResults(input.Bindings, StatusSkipped, ReasonActivationUnavailable),
		Status:         StatusSkipped,
		Warnings:       activationUnavailableWarnings(input.Plan.RequestedModes),
	})
}

func planFailedActivationResult(input ActivationRequest) ActivationResult {
	result := ActivationResult{
		ID:             input.ActivationID,
		PlanID:         input.Plan.ID,
		RequestedModes: input.Plan.RequestedModes,
		Bindings:       activationBindingResults(input.Bindings, StatusFailed, ReasonActivationUnavailable),
		Status:         StatusFailed,
		Errors:         input.Plan.Errors,
	}
	if len(result.Errors) == 0 {
		result.Errors = []SanitizedError{activationFailedError()}
	}
	return SanitizeActivationResultMetadata(result)
}

func adapterFailedActivationResult(input ActivationRequest) ActivationResult {
	return SanitizeActivationResultMetadata(ActivationResult{
		ID:             input.ActivationID,
		PlanID:         input.Plan.ID,
		RequestedModes: input.Plan.RequestedModes,
		Bindings:       activationBindingResults(input.Bindings, StatusFailed, ReasonActivationUnavailable),
		Status:         StatusFailed,
		Errors:         []SanitizedError{activationFailedError()},
	})
}

func activationModeMetadataFailedActivationResult(input ActivationRequest, errors []SanitizedError) ActivationResult {
	resultErrors := append([]SanitizedError{}, errors...)
	resultErrors = append(resultErrors, input.Plan.Errors...)
	return SanitizeActivationResultMetadata(ActivationResult{
		ID:             input.ActivationID,
		PlanID:         input.Plan.ID,
		RequestedModes: input.Plan.RequestedModes,
		Bindings:       activationBindingResults(input.Bindings, StatusFailed, ReasonUnsupportedMode),
		Status:         StatusFailed,
		Errors:         resultErrors,
	})
}

func finalizeAdapterActivationResult(input ActivationRequest, raw ActivationResult) ActivationResult {
	normalized := NormalizeActivationResultMetadata(raw)
	adapterActiveModes := normalized.ActiveModes
	if sanitizeIdentifier(normalized.ID) == "" {
		normalized.ID = input.ActivationID
	}
	if sanitizeIdentifier(normalized.PlanID) == "" {
		normalized.PlanID = input.Plan.ID
	}
	normalized.RequestedModes = input.Plan.RequestedModes
	normalized.Bindings = activationBindingResultsForInput(input, normalized.Bindings)
	normalized.Warnings = appendHTTPProxyActivationWarnings(input, adapterActiveModes, normalized.Bindings, normalized.Warnings)
	normalized.Warnings = appendLegacyAuthCompatibilityWarnings(input, normalized.Warnings)
	normalized.ActiveModes = activationActiveModesForInput(input, normalized)

	result := SanitizeActivationResultMetadata(normalized)
	if result.ID == "" || result.PlanID == "" {
		return ActivationResult{}
	}
	if result.Status == StatusFailed || len(result.Errors) > 0 {
		result.Status = StatusFailed
		result.ActiveModes = nil
		result.Bindings = activationBindingResults(input.Bindings, StatusFailed, ReasonActivationUnavailable)
		if len(result.Errors) == 0 {
			result.Errors = []SanitizedError{activationFailedError()}
		}
		return SanitizeActivationResultMetadata(result)
	}
	if result.Status == "" {
		if len(result.ActiveModes) > 0 {
			result.Status = StatusActive
		} else {
			result.Status = StatusSkipped
		}
	}
	if result.Status == StatusActive && len(result.ActiveModes) == 0 {
		result.Status = StatusSkipped
	}
	if result.Status == StatusSkipped && len(result.Warnings) == 0 {
		result.Warnings = activationUnavailableWarnings(input.Plan.RequestedModes)
	}
	return SanitizeActivationResultMetadata(result)
}

func activationFailedError() SanitizedError {
	return SanitizedError{
		Code:       ErrorActivationFailed,
		Field:      "adapter",
		ReasonCode: ReasonActivationUnavailable,
	}
}

func activationUnavailableWarnings(modes []Mode) []Warning {
	if modes == nil {
		return nil
	}
	warnings := make([]Warning, 0, len(modes))
	seen := newPlanModeSet()
	for _, mode := range normalizeModeRecords(modes) {
		if !validMode(mode) || seen.contains(mode) {
			continue
		}
		seen.add(mode)
		warning := Warning{
			Code:       WarningAdapterUnavailable,
			ReasonCode: ReasonActivationUnavailable,
			Mode:       mode,
		}
		if mode == ModeLegacyAuthSync {
			warning.Code = WarningLegacyAuthCompatibility
			warning.ReasonCode = ReasonCompatibilityMode
		}
		warnings = append(warnings, warning)
	}
	return warnings
}

func activationBindingResults(bindings []Binding, status Status, fallbackReason ReasonCode) []BindingActivationResult {
	if bindings == nil {
		return nil
	}
	results := make([]BindingActivationResult, 0, len(bindings))
	for _, binding := range SanitizeBindingMetadataRecords(bindings) {
		reason := fallbackReason
		if binding.DeliveryMode == ModeLegacyAuthSync && fallbackReason == ReasonActivationUnavailable {
			reason = ReasonCompatibilityMode
		}
		results = append(results, BindingActivationResult{
			BindingID:    binding.ID,
			ServiceID:    binding.ServiceID,
			DeliveryMode: binding.DeliveryMode,
			Outcome:      status,
			Status:       status,
			ReasonCode:   reason,
		})
	}
	return results
}

func activationBindingResultsForInput(input ActivationRequest, raw []BindingActivationResult) []BindingActivationResult {
	if raw == nil {
		return nil
	}
	allowed := activationBindingsByID(input.Bindings)
	sanitized := SanitizeBindingActivationResultMetadataRecords(raw)
	results := make([]BindingActivationResult, 0, len(sanitized))
	for _, result := range sanitized {
		binding, ok := allowed[result.BindingID]
		if !ok || result.DeliveryMode != binding.DeliveryMode {
			continue
		}
		result.ServiceID = binding.ServiceID
		result = normalizeActivationBindingOutcome(result)
		if result.DeliveryMode == ModeLegacyAuthSync {
			if result.Status == StatusActive {
				result.Status = StatusSkipped
				result.Outcome = StatusSkipped
			}
			if result.ReasonCode == "" || result.ReasonCode == ReasonRequested {
				result.ReasonCode = ReasonCompatibilityMode
			}
		}
		if result.DeliveryMode == ModeHTTPProxy && result.Status == StatusActive && !httpProxyActivationAllowed(input.Plan, binding) {
			result.Status = StatusSkipped
			result.Outcome = StatusSkipped
			result.ReasonCode = ReasonMissingServiceBinding
		}
		results = append(results, result)
	}
	return results
}

func activationBindingsByID(bindings []Binding) map[string]Binding {
	if len(bindings) == 0 {
		return nil
	}
	out := make(map[string]Binding, len(bindings))
	for _, binding := range SanitizeBindingMetadataRecords(bindings) {
		out[binding.ID] = binding
	}
	return out
}

func activationActiveModesForInput(input ActivationRequest, result ActivationResult) []Mode {
	requested := newPlanModeSet()
	for _, mode := range input.Plan.RequestedModes {
		requested.add(mode)
	}
	active := newPlanModeSet()
	if len(input.Bindings) == 0 && (result.Status == "" || result.Status == StatusActive) {
		for _, mode := range result.ActiveModes {
			mode = normalizeMode(mode)
			if mode == ModeHTTPProxy || mode == ModeLegacyAuthSync {
				continue
			}
			if requested.contains(mode) {
				active.add(mode)
			}
		}
	}
	for _, binding := range result.Bindings {
		if binding.DeliveryMode == ModeLegacyAuthSync {
			continue
		}
		if binding.Status == StatusActive && requested.contains(binding.DeliveryMode) {
			active.add(binding.DeliveryMode)
		}
	}
	return active.ordered()
}

func activationModeMetadataErrors(request ActivationRequest) []SanitizedError {
	var errors []SanitizedError
	errors = append(errors, activationModeListMetadataErrors("plan.requestedModes", request.Plan.RequestedModes)...)
	for i, binding := range request.Bindings {
		if err, ok := activationModeMetadataError("bindings.deliveryMode", binding.DeliveryMode, &i); ok {
			errors = append(errors, err)
		}
	}
	return SanitizeSanitizedErrorRecords(errors)
}

func activationModeListMetadataErrors(field string, modes []Mode) []SanitizedError {
	if modes == nil {
		return nil
	}
	errors := make([]SanitizedError, 0, len(modes))
	for i, mode := range modes {
		if err, ok := activationModeMetadataError(field, mode, &i); ok {
			errors = append(errors, err)
		}
	}
	return errors
}

func activationModeMetadataError(field string, mode Mode, index *int) (SanitizedError, bool) {
	raw := string(mode)
	normalized := normalizeMode(mode)
	err := SanitizedError{
		Field:      field,
		ReasonCode: ReasonUnsupportedMode,
	}
	if index != nil {
		idx := *index
		err.Index = &idx
	}
	switch {
	case strings.TrimSpace(raw) == "":
		err.Code = ErrorMissingRequiredField
	case unsafeCredentialDeliveryFreeformMetadata(string(normalized)):
		err.Code = ErrorUnsafeMetadata
	case !validMode(normalized):
		err.Code = ErrorUnsupportedMode
	default:
		return SanitizedError{}, false
	}
	return err, true
}

func normalizeActivationBindingOutcome(result BindingActivationResult) BindingActivationResult {
	if result.Status == "" && result.Outcome != "" {
		result.Status = result.Outcome
	}
	if result.Outcome == "" {
		result.Outcome = result.Status
	}
	return result
}

func httpProxyActivationAllowed(plan Plan, binding Binding) bool {
	if binding.DeliveryMode != ModeHTTPProxy || binding.ServiceID == "" {
		return false
	}
	if !activationModeRecordsContain(plan.RequestedModes, ModeHTTPProxy) ||
		!activationModeRecordsContain(plan.ActiveModes, ModeHTTPProxy) ||
		plan.NetworkProxySessionID == "" {
		return false
	}
	proof := SanitizeHTTPProxyProofMetadataPtr(plan.HTTPProxyProof)
	if proof == nil ||
		proof.NetworkEnforcement == nil ||
		proof.BindingID != binding.ID ||
		proof.SecretID != binding.SecretRef ||
		proof.NetworkEnforcement.NetworkProxySessionID != plan.NetworkProxySessionID ||
		proof.NetworkEnforcement.PolicySnapshotID == "" ||
		proof.NetworkEnforcement.PolicySnapshotID != binding.PolicySnapshotID ||
		proof.SecretBrokerSessionID == "" ||
		proof.CredentialProxyPlanID == "" ||
		proof.CredentialProxySessionID == "" ||
		proof.CredentialProxyBindingID == "" ||
		!sandbox.SandboxNetworkEnforcementProofProvesActiveHTTPProxy(*proof.NetworkEnforcement) {
		return false
	}
	return binding.NetworkProxySessionID == "" || binding.NetworkProxySessionID == plan.NetworkProxySessionID
}

func appendHTTPProxyActivationWarnings(input ActivationRequest, adapterActiveModes []Mode, bindings []BindingActivationResult, warnings []Warning) []Warning {
	if !activationModeRecordsContain(input.Plan.RequestedModes, ModeHTTPProxy) {
		return warnings
	}
	if activationHasActiveBindingForMode(bindings, ModeHTTPProxy) {
		return warnings
	}
	if activationHasSkippedBindingForMode(bindings, ModeHTTPProxy) ||
		activationModeRecordsContain(adapterActiveModes, ModeHTTPProxy) {
		return appendActivationWarningIfMissing(warnings, Warning{
			Code:       WarningActivationSkipped,
			ReasonCode: ReasonMissingServiceBinding,
			Mode:       ModeHTTPProxy,
		})
	}
	return warnings
}

func appendLegacyAuthCompatibilityWarnings(input ActivationRequest, warnings []Warning) []Warning {
	if !activationModeRecordsContain(input.Plan.RequestedModes, ModeLegacyAuthSync) {
		return warnings
	}
	return appendActivationWarningIfMissing(warnings, Warning{
		Code:       WarningLegacyAuthCompatibility,
		ReasonCode: ReasonCompatibilityMode,
		Mode:       ModeLegacyAuthSync,
	})
}

func appendActivationWarningIfMissing(warnings []Warning, warning Warning) []Warning {
	for _, existing := range SanitizeWarningMetadataRecords(warnings) {
		if existing.Code == warning.Code && existing.ReasonCode == warning.ReasonCode && existing.Mode == warning.Mode && existing.BindingID == warning.BindingID {
			return warnings
		}
	}
	return append(warnings, warning)
}

func activationHasActiveBindingForMode(bindings []BindingActivationResult, mode Mode) bool {
	for _, binding := range bindings {
		if binding.DeliveryMode == mode && binding.Status == StatusActive {
			return true
		}
	}
	return false
}

func activationHasSkippedBindingForMode(bindings []BindingActivationResult, mode Mode) bool {
	for _, binding := range bindings {
		if binding.DeliveryMode == mode && binding.Status == StatusSkipped {
			return true
		}
	}
	return false
}

func activationModeRecordsContain(modes []Mode, target Mode) bool {
	for _, mode := range normalizeModeRecords(modes) {
		if mode == target {
			return true
		}
	}
	return false
}
