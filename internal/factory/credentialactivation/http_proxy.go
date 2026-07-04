package credentialactivation

import (
	"strings"

	"github.com/jywlabs/hal/internal/credentialdelivery"
)

var _ credentialdelivery.ActivationAdapter = (*HTTPProxyHandoffAdapter)(nil)

// HTTPProxyHandoffOptions configures explicit http_proxy handoff activation
// from existing credential and network proxy proof metadata.
type HTTPProxyHandoffOptions struct {
	Enabled bool
}

// HTTPProxyHandoffAdapter activates http_proxy metadata only when the
// sanitized delivery plan already carries valid safe handoff proof metadata.
type HTTPProxyHandoffAdapter struct {
	enabled bool
	calls   []credentialdelivery.ActivationRequest
}

// NewHTTPProxyHandoffAdapter returns a disabled-by-default http_proxy handoff
// adapter. Callers must opt in with Enabled.
func NewHTTPProxyHandoffAdapter(options HTTPProxyHandoffOptions) *HTTPProxyHandoffAdapter {
	return &HTTPProxyHandoffAdapter{enabled: options.Enabled}
}

// Calls returns sanitized activation requests observed by the adapter.
func (a *HTTPProxyHandoffAdapter) Calls() []credentialdelivery.ActivationRequest {
	if a == nil || a.calls == nil {
		return nil
	}
	calls := make([]credentialdelivery.ActivationRequest, len(a.calls))
	for i, call := range a.calls {
		calls[i] = credentialdelivery.SanitizeActivationRequestMetadata(call)
	}
	return calls
}

// ActivateCredentialDelivery implements credentialdelivery.ActivationAdapter.
func (a *HTTPProxyHandoffAdapter) ActivateCredentialDelivery(input credentialdelivery.SanitizedActivationRequest) (credentialdelivery.ActivationResult, error) {
	request := input.Request()
	if a != nil {
		a.calls = append(a.calls, request)
	}
	if request.ActivationID == "" || request.Plan.ID == "" {
		return credentialdelivery.ActivationResult{}, nil
	}
	if a == nil || !a.enabled {
		return httpProxyDisabledResult(request), nil
	}

	resolution := resolveHTTPProxyHandoff(request)
	if !resolution.active {
		return httpProxySkippedResult(request, resolution.bindings, resolution.warnings, resolution.reason), nil
	}

	return credentialdelivery.SanitizeActivationResultMetadata(credentialdelivery.ActivationResult{
		ID:             request.ActivationID,
		PlanID:         request.Plan.ID,
		RequestedModes: request.Plan.RequestedModes,
		ActiveModes:    []credentialdelivery.Mode{credentialdelivery.ModeHTTPProxy},
		Bindings:       resolution.bindings,
		ProofRefs:      resolution.proofs,
		Status:         credentialdelivery.StatusActive,
		ReasonCode:     credentialdelivery.ReasonRequested,
		Warnings:       resolution.warnings,
	}), nil
}

type httpProxyHandoffResolution struct {
	bindings []credentialdelivery.BindingActivationResult
	proofs   []credentialdelivery.ActivationProofReference
	warnings []credentialdelivery.Warning
	active   bool
	reason   credentialdelivery.ReasonCode
}

func resolveHTTPProxyHandoff(request credentialdelivery.ActivationRequest) httpProxyHandoffResolution {
	resolution := httpProxyHandoffResolution{
		bindings: make([]credentialdelivery.BindingActivationResult, 0, len(request.Bindings)),
		proofs:   make([]credentialdelivery.ActivationProofReference, 0, len(request.Bindings)),
	}
	for _, binding := range request.Bindings {
		if binding.DeliveryMode != credentialdelivery.ModeHTTPProxy {
			resolution.bindings = append(resolution.bindings, credentialdelivery.BindingActivationResult{
				BindingID:    binding.ID,
				DeliveryMode: binding.DeliveryMode,
				Status:       credentialdelivery.StatusSkipped,
				ReasonCode:   credentialdelivery.ReasonUnsupportedMode,
			})
			resolution.warnings = appendHTTPProxyWarningIfMissing(resolution.warnings, credentialdelivery.Warning{
				Code:       credentialdelivery.WarningUnsupportedMode,
				ReasonCode: credentialdelivery.ReasonUnsupportedMode,
				BindingID:  binding.ID,
				Mode:       binding.DeliveryMode,
			})
			continue
		}

		reason := credentialdelivery.HTTPProxyProofActivationReason(request.Plan, binding)
		if reason != credentialdelivery.ReasonRequested {
			resolution.reason = reason
			resolution.bindings = append(resolution.bindings, credentialdelivery.BindingActivationResult{
				BindingID:    binding.ID,
				DeliveryMode: credentialdelivery.ModeHTTPProxy,
				Status:       credentialdelivery.StatusSkipped,
				ReasonCode:   reason,
			})
			resolution.warnings = appendHTTPProxyWarningIfMissing(resolution.warnings, credentialdelivery.Warning{
				Code:       credentialdelivery.WarningActivationSkipped,
				ReasonCode: reason,
				BindingID:  binding.ID,
				Mode:       credentialdelivery.ModeHTTPProxy,
			})
			continue
		}

		proofID := httpProxyHandoffProofID(request.ActivationID, binding.ID)
		resolution.active = true
		resolution.proofs = append(resolution.proofs, credentialdelivery.ActivationProofReference{
			ProofID:      proofID,
			BindingID:    binding.ID,
			DeliveryMode: credentialdelivery.ModeHTTPProxy,
		})
		resolution.bindings = append(resolution.bindings, credentialdelivery.BindingActivationResult{
			BindingID:    binding.ID,
			DeliveryMode: credentialdelivery.ModeHTTPProxy,
			Status:       credentialdelivery.StatusActive,
			ReasonCode:   credentialdelivery.ReasonRequested,
			ProofRef:     proofID,
		})
	}
	if !resolution.active && resolution.reason == "" {
		resolution.reason = credentialdelivery.ReasonMissingActivationProof
	}
	return resolution
}

func httpProxyDisabledResult(request credentialdelivery.ActivationRequest) credentialdelivery.ActivationResult {
	return credentialdelivery.SanitizeActivationResultMetadata(credentialdelivery.ActivationResult{
		ID:             request.ActivationID,
		PlanID:         request.Plan.ID,
		RequestedModes: request.Plan.RequestedModes,
		Bindings:       httpProxyBindingResults(request.Bindings, credentialdelivery.StatusDisabled, credentialdelivery.ReasonDisabled),
		Status:         credentialdelivery.StatusDisabled,
		ReasonCode:     credentialdelivery.ReasonDisabled,
	})
}

func httpProxySkippedResult(request credentialdelivery.ActivationRequest, bindings []credentialdelivery.BindingActivationResult, warnings []credentialdelivery.Warning, reason credentialdelivery.ReasonCode) credentialdelivery.ActivationResult {
	if reason == "" {
		reason = credentialdelivery.ReasonMissingActivationProof
	}
	if len(bindings) == 0 {
		bindings = httpProxyBindingResults(request.Bindings, credentialdelivery.StatusSkipped, reason)
	}
	if len(warnings) == 0 {
		warnings = httpProxyActivationWarnings(request.Bindings, reason)
	}
	return credentialdelivery.SanitizeActivationResultMetadata(credentialdelivery.ActivationResult{
		ID:             request.ActivationID,
		PlanID:         request.Plan.ID,
		RequestedModes: request.Plan.RequestedModes,
		Bindings:       bindings,
		Status:         credentialdelivery.StatusSkipped,
		ReasonCode:     reason,
		Warnings:       warnings,
	})
}

func httpProxyBindingResults(bindings []credentialdelivery.Binding, status credentialdelivery.Status, reason credentialdelivery.ReasonCode) []credentialdelivery.BindingActivationResult {
	if bindings == nil {
		return nil
	}
	out := make([]credentialdelivery.BindingActivationResult, 0, len(bindings))
	for _, binding := range credentialdelivery.SanitizeBindingMetadataRecords(bindings) {
		out = append(out, credentialdelivery.BindingActivationResult{
			BindingID:    binding.ID,
			DeliveryMode: binding.DeliveryMode,
			Status:       status,
			ReasonCode:   reason,
		})
	}
	return out
}

func httpProxyActivationWarnings(bindings []credentialdelivery.Binding, reason credentialdelivery.ReasonCode) []credentialdelivery.Warning {
	if len(bindings) == 0 {
		return nil
	}
	warnings := make([]credentialdelivery.Warning, 0, len(bindings))
	for _, binding := range credentialdelivery.SanitizeBindingMetadataRecords(bindings) {
		if binding.DeliveryMode != credentialdelivery.ModeHTTPProxy {
			continue
		}
		warnings = appendHTTPProxyWarningIfMissing(warnings, credentialdelivery.Warning{
			Code:       credentialdelivery.WarningActivationSkipped,
			ReasonCode: reason,
			BindingID:  binding.ID,
			Mode:       credentialdelivery.ModeHTTPProxy,
		})
	}
	if len(warnings) == 0 {
		return nil
	}
	return warnings
}

func appendHTTPProxyWarningIfMissing(warnings []credentialdelivery.Warning, warning credentialdelivery.Warning) []credentialdelivery.Warning {
	for _, existing := range credentialdelivery.SanitizeWarningMetadataRecords(warnings) {
		if existing.Code == warning.Code && existing.ReasonCode == warning.ReasonCode && existing.Mode == warning.Mode && existing.BindingID == warning.BindingID {
			return warnings
		}
	}
	return append(warnings, warning)
}

func httpProxyHandoffProofID(activationID, bindingID string) string {
	return httpProxySafeIdentifier(activationID + "-" + bindingID + "-http-proxy-handoff-proof")
}

func httpProxySafeIdentifier(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return ""
		}
	}
	if httpProxyIdentifierLooksUnsafe(value) {
		return ""
	}
	return value
}

func httpProxyIdentifierLooksUnsafe(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"ghp_",
		"github_pat_",
		"sk-",
		"authorization",
		"bearer",
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
