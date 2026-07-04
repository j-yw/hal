package credentialactivation

import (
	"strings"

	"github.com/jywlabs/hal/internal/credentialdelivery"
	halfactory "github.com/jywlabs/hal/internal/factory"
)

var _ credentialdelivery.ActivationAdapter = (*FileTmpfsSimulationAdapter)(nil)

// FileTmpfsSimulationOptions configures explicit file_tmpfs simulation against
// an existing in-memory broker session. It never receives a mount path.
type FileTmpfsSimulationOptions struct {
	Enabled               bool
	Broker                *halfactory.InMemorySecretBroker
	SecretBrokerSessionID string
}

// FileTmpfsSimulationAdapter simulates file_tmpfs activation with synthetic
// proof metadata only. It verifies broker secret presence in memory but never
// writes files or returns host path metadata.
type FileTmpfsSimulationAdapter struct {
	enabled               bool
	broker                *halfactory.InMemorySecretBroker
	secretBrokerSessionID string
	calls                 []credentialdelivery.ActivationRequest
}

// NewFileTmpfsSimulationAdapter returns a disabled-by-default file_tmpfs
// simulation adapter. Callers must set Enabled to activate broker-backed
// simulation metadata.
func NewFileTmpfsSimulationAdapter(options FileTmpfsSimulationOptions) *FileTmpfsSimulationAdapter {
	return &FileTmpfsSimulationAdapter{
		enabled:               options.Enabled,
		broker:                options.Broker,
		secretBrokerSessionID: tmpfsSafeIdentifier(options.SecretBrokerSessionID),
	}
}

// Calls returns sanitized activation requests observed by the adapter.
func (a *FileTmpfsSimulationAdapter) Calls() []credentialdelivery.ActivationRequest {
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
func (a *FileTmpfsSimulationAdapter) ActivateCredentialDelivery(input credentialdelivery.SanitizedActivationRequest) (credentialdelivery.ActivationResult, error) {
	request := input.Request()
	if a != nil {
		a.calls = append(a.calls, request)
	}
	if request.ActivationID == "" || request.Plan.ID == "" {
		return credentialdelivery.ActivationResult{}, nil
	}
	if a == nil || !a.enabled {
		return tmpfsDisabledResult(request), nil
	}
	if a.broker == nil || a.secretBrokerSessionID == "" {
		return tmpfsFailedResult(request, credentialdelivery.ReasonActivationUnavailable), nil
	}
	session, ok := a.broker.SessionMetadata(a.secretBrokerSessionID)
	if !ok {
		return tmpfsFailedResult(request, credentialdelivery.ReasonActivationUnavailable), nil
	}
	if !tmpfsSessionSupportsActiveFileTmpfs(session) {
		return tmpfsFailedResult(request, credentialdelivery.ReasonMissingActivationProof), nil
	}

	resolution := a.resolve(request)
	if resolution.failed {
		return tmpfsFailedResult(request, resolution.reason), nil
	}
	if !resolution.active {
		return tmpfsSkippedResult(request, resolution.bindings, resolution.warnings, credentialdelivery.ReasonUnsupportedMode), nil
	}

	return credentialdelivery.SanitizeActivationResultMetadata(credentialdelivery.ActivationResult{
		ID:             request.ActivationID,
		PlanID:         request.Plan.ID,
		RequestedModes: request.Plan.RequestedModes,
		ActiveModes:    []credentialdelivery.Mode{credentialdelivery.ModeFileTmpfs},
		Bindings:       resolution.bindings,
		ProofRefs:      resolution.proofs,
		Status:         credentialdelivery.StatusActive,
		ReasonCode:     credentialdelivery.ReasonRequested,
		Warnings:       resolution.warnings,
	}), nil
}

type tmpfsResolution struct {
	bindings []credentialdelivery.BindingActivationResult
	proofs   []credentialdelivery.ActivationProofReference
	warnings []credentialdelivery.Warning
	active   bool
	failed   bool
	reason   credentialdelivery.ReasonCode
}

func (a *FileTmpfsSimulationAdapter) resolve(request credentialdelivery.ActivationRequest) tmpfsResolution {
	resolution := tmpfsResolution{
		bindings: make([]credentialdelivery.BindingActivationResult, 0, len(request.Bindings)),
		proofs:   make([]credentialdelivery.ActivationProofReference, 0, len(request.Bindings)),
	}
	for _, binding := range request.Bindings {
		if binding.DeliveryMode != credentialdelivery.ModeFileTmpfs {
			resolution.bindings = append(resolution.bindings, credentialdelivery.BindingActivationResult{
				BindingID:    binding.ID,
				DeliveryMode: binding.DeliveryMode,
				Status:       credentialdelivery.StatusSkipped,
				ReasonCode:   credentialdelivery.ReasonUnsupportedMode,
			})
			resolution.warnings = appendTmpfsWarningIfMissing(resolution.warnings, credentialdelivery.Warning{
				Code:       credentialdelivery.WarningUnsupportedMode,
				ReasonCode: credentialdelivery.ReasonUnsupportedMode,
				BindingID:  binding.ID,
				Mode:       binding.DeliveryMode,
			})
			continue
		}

		if !a.secretPresent(binding.SecretRef) {
			resolution.failed = true
			resolution.reason = credentialdelivery.ReasonMissingSecretReference
			resolution.bindings = append(resolution.bindings, credentialdelivery.BindingActivationResult{
				BindingID:    binding.ID,
				DeliveryMode: credentialdelivery.ModeFileTmpfs,
				Status:       credentialdelivery.StatusFailed,
				ReasonCode:   credentialdelivery.ReasonMissingSecretReference,
			})
			resolution.warnings = appendTmpfsWarningIfMissing(resolution.warnings, credentialdelivery.Warning{
				Code:       credentialdelivery.WarningActivationSkipped,
				ReasonCode: credentialdelivery.ReasonMissingSecretReference,
				BindingID:  binding.ID,
				Mode:       credentialdelivery.ModeFileTmpfs,
			})
			continue
		}

		proofID := tmpfsSimulationProofID(a.secretBrokerSessionID, binding.ID)
		resolution.active = true
		resolution.proofs = append(resolution.proofs, credentialdelivery.ActivationProofReference{
			ProofID:      proofID,
			BindingID:    binding.ID,
			DeliveryMode: credentialdelivery.ModeFileTmpfs,
		})
		resolution.bindings = append(resolution.bindings, credentialdelivery.BindingActivationResult{
			BindingID:    binding.ID,
			DeliveryMode: credentialdelivery.ModeFileTmpfs,
			Status:       credentialdelivery.StatusActive,
			ReasonCode:   credentialdelivery.ReasonRequested,
			ProofRef:     proofID,
		})
	}
	if resolution.failed && resolution.reason == "" {
		resolution.reason = credentialdelivery.ReasonActivationUnavailable
	}
	return resolution
}

func (a *FileTmpfsSimulationAdapter) secretPresent(secretRef string) bool {
	if a == nil || a.broker == nil || a.secretBrokerSessionID == "" {
		return false
	}
	resolved, ok := a.broker.LookupSecretByID(a.secretBrokerSessionID, secretRef)
	return ok && strings.TrimSpace(resolved.Value) != ""
}

func tmpfsSessionSupportsActiveFileTmpfs(session halfactory.SecretBrokerSessionMetadata) bool {
	if session.DeliveryModes == nil {
		return false
	}
	return tmpfsDeliveryModesContain(session.DeliveryModes.RequestedModes, halfactory.SecretBrokerDeliveryModeFileTmpfs) &&
		tmpfsDeliveryModesContain(session.DeliveryModes.ActiveModes, halfactory.SecretBrokerDeliveryModeFileTmpfs)
}

func tmpfsDeliveryModesContain(modes []string, want string) bool {
	for _, mode := range modes {
		if strings.TrimSpace(mode) == want {
			return true
		}
	}
	return false
}

func tmpfsDisabledResult(request credentialdelivery.ActivationRequest) credentialdelivery.ActivationResult {
	return credentialdelivery.SanitizeActivationResultMetadata(credentialdelivery.ActivationResult{
		ID:             request.ActivationID,
		PlanID:         request.Plan.ID,
		RequestedModes: request.Plan.RequestedModes,
		Bindings:       tmpfsBindingResults(request.Bindings, credentialdelivery.StatusDisabled, credentialdelivery.ReasonDisabled),
		Status:         credentialdelivery.StatusDisabled,
		ReasonCode:     credentialdelivery.ReasonDisabled,
	})
}

func tmpfsFailedResult(request credentialdelivery.ActivationRequest, reason credentialdelivery.ReasonCode) credentialdelivery.ActivationResult {
	if reason == "" {
		reason = credentialdelivery.ReasonActivationUnavailable
	}
	return credentialdelivery.SanitizeActivationResultMetadata(credentialdelivery.ActivationResult{
		ID:             request.ActivationID,
		PlanID:         request.Plan.ID,
		RequestedModes: request.Plan.RequestedModes,
		Bindings:       tmpfsBindingResults(request.Bindings, credentialdelivery.StatusFailed, reason),
		Status:         credentialdelivery.StatusFailed,
		ReasonCode:     reason,
		Warnings:       tmpfsActivationWarnings(request.Bindings, reason),
	})
}

func tmpfsSkippedResult(request credentialdelivery.ActivationRequest, bindings []credentialdelivery.BindingActivationResult, warnings []credentialdelivery.Warning, reason credentialdelivery.ReasonCode) credentialdelivery.ActivationResult {
	if reason == "" {
		reason = credentialdelivery.ReasonActivationUnavailable
	}
	if len(bindings) == 0 {
		bindings = tmpfsBindingResults(request.Bindings, credentialdelivery.StatusSkipped, reason)
	}
	if len(warnings) == 0 {
		warnings = tmpfsActivationWarnings(request.Bindings, reason)
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

func tmpfsBindingResults(bindings []credentialdelivery.Binding, status credentialdelivery.Status, reason credentialdelivery.ReasonCode) []credentialdelivery.BindingActivationResult {
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

func tmpfsActivationWarnings(bindings []credentialdelivery.Binding, reason credentialdelivery.ReasonCode) []credentialdelivery.Warning {
	if len(bindings) == 0 {
		return nil
	}
	warnings := make([]credentialdelivery.Warning, 0, len(bindings))
	for _, binding := range credentialdelivery.SanitizeBindingMetadataRecords(bindings) {
		if binding.DeliveryMode != credentialdelivery.ModeFileTmpfs {
			continue
		}
		warnings = appendTmpfsWarningIfMissing(warnings, credentialdelivery.Warning{
			Code:       credentialdelivery.WarningActivationSkipped,
			ReasonCode: reason,
			BindingID:  binding.ID,
			Mode:       credentialdelivery.ModeFileTmpfs,
		})
	}
	if len(warnings) == 0 {
		return nil
	}
	return warnings
}

func appendTmpfsWarningIfMissing(warnings []credentialdelivery.Warning, warning credentialdelivery.Warning) []credentialdelivery.Warning {
	for _, existing := range credentialdelivery.SanitizeWarningMetadataRecords(warnings) {
		if existing.Code == warning.Code && existing.ReasonCode == warning.ReasonCode && existing.Mode == warning.Mode && existing.BindingID == warning.BindingID {
			return warnings
		}
	}
	return append(warnings, warning)
}

func tmpfsSimulationProofID(activationID, bindingID string) string {
	return tmpfsSafeIdentifier(activationID + "-" + bindingID + "-tmpfs-simulation-proof")
}

func tmpfsSafeIdentifier(value string) string {
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
	if tmpfsIdentifierLooksUnsafe(value) {
		return ""
	}
	return value
}

func tmpfsIdentifierLooksUnsafe(value string) bool {
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
