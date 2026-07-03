package credentialdelivery

import (
	"encoding/json"
	"strings"
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
	sanitizedInput := NewSanitizedActivationRequest(request)
	input := sanitizedInput.Request()
	if input.ActivationID == "" || input.Plan.ID == "" {
		return ActivationResult{}
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

func finalizeAdapterActivationResult(input ActivationRequest, raw ActivationResult) ActivationResult {
	normalized := NormalizeActivationResultMetadata(raw)
	if sanitizeIdentifier(normalized.ID) == "" {
		normalized.ID = input.ActivationID
	}
	if sanitizeIdentifier(normalized.PlanID) == "" {
		normalized.PlanID = input.Plan.ID
	}
	normalized.RequestedModes = input.Plan.RequestedModes
	normalized.Bindings = activationBindingResultsForInput(input, normalized.Bindings)
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
			DeliveryMode: binding.DeliveryMode,
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
	allowed := activationBindingModesByID(input.Bindings)
	sanitized := SanitizeBindingActivationResultMetadataRecords(raw)
	results := make([]BindingActivationResult, 0, len(sanitized))
	for _, result := range sanitized {
		mode, ok := allowed[result.BindingID]
		if !ok || result.DeliveryMode != mode {
			continue
		}
		results = append(results, result)
	}
	return results
}

func activationBindingModesByID(bindings []Binding) map[string]Mode {
	if len(bindings) == 0 {
		return nil
	}
	out := make(map[string]Mode, len(bindings))
	for _, binding := range SanitizeBindingMetadataRecords(bindings) {
		out[binding.ID] = binding.DeliveryMode
	}
	return out
}

func activationActiveModesForInput(input ActivationRequest, result ActivationResult) []Mode {
	requested := newPlanModeSet()
	for _, mode := range input.Plan.RequestedModes {
		requested.add(mode)
	}
	active := newPlanModeSet()
	for _, mode := range result.ActiveModes {
		if requested.contains(normalizeMode(mode)) {
			active.add(mode)
		}
	}
	for _, binding := range result.Bindings {
		if binding.Status == StatusActive && requested.contains(binding.DeliveryMode) {
			active.add(binding.DeliveryMode)
		}
	}
	return active.ordered()
}
