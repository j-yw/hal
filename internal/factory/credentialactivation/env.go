package credentialactivation

import (
	"strings"

	"github.com/jywlabs/hal/internal/credentialdelivery"
	halfactory "github.com/jywlabs/hal/internal/factory"
)

var _ credentialdelivery.ActivationAdapter = (*EnvAdapter)(nil)

// EnvOptions configures explicit env:NAME activation into the in-memory secret
// broker. Environment is injected so this path never reads process-global
// environment state directly.
type EnvOptions struct {
	Enabled           bool
	Broker            *halfactory.InMemorySecretBroker
	Environment       halfactory.RunSecretLookup
	SecretBrokerID    string
	RequiredSecretIDs []string
}

// EnvAdapter resolves opted-in env:NAME bindings into the existing in-memory
// broker session and returns only safe activation metadata.
type EnvAdapter struct {
	enabled           bool
	broker            *halfactory.InMemorySecretBroker
	environment       halfactory.RunSecretLookup
	secretBrokerID    string
	requiredSecretIDs []string
}

// NewEnvAdapter returns an env-backed activation adapter. Callers must set
// Enabled to allow environment resolution.
func NewEnvAdapter(options EnvOptions) *EnvAdapter {
	return &EnvAdapter{
		enabled:           options.Enabled,
		broker:            options.Broker,
		environment:       options.Environment,
		secretBrokerID:    strings.TrimSpace(options.SecretBrokerID),
		requiredSecretIDs: append([]string(nil), options.RequiredSecretIDs...),
	}
}

// ActivateCredentialDelivery implements credentialdelivery.ActivationAdapter.
func (a *EnvAdapter) ActivateCredentialDelivery(input credentialdelivery.SanitizedActivationRequest) (credentialdelivery.ActivationResult, error) {
	request := input.Request()
	if request.ActivationID == "" || request.Plan.ID == "" {
		return credentialdelivery.ActivationResult{}, nil
	}
	if a == nil || !a.enabled {
		return envDisabledResult(request), nil
	}
	if a.broker == nil || a.environment == nil {
		return envFailedResult(request, credentialdelivery.ReasonActivationUnavailable), nil
	}

	resolution := a.resolve(request)
	if resolution.failed {
		return envFailedResult(request, resolution.reason), nil
	}
	if len(resolution.resolved) == 0 {
		return envSkippedResult(request, credentialdelivery.ReasonActivationUnavailable), nil
	}

	sessionID := a.secretBrokerID
	if sessionID == "" {
		sessionID = request.ActivationID + "-broker-session"
	}
	if _, err := a.broker.CreateSession(halfactory.SecretBrokerSessionRequest{
		ID:                     sessionID,
		ResolvedSecrets:        resolution.resolved,
		RequestedDeliveryModes: []string{halfactory.SecretBrokerDeliveryModeEnv},
		ActiveDeliveryModes:    []string{halfactory.SecretBrokerDeliveryModeEnv},
	}); err != nil {
		return envFailedResult(request, credentialdelivery.ReasonActivationUnavailable), nil
	}

	return credentialdelivery.SanitizeActivationResultMetadata(credentialdelivery.ActivationResult{
		ID:             request.ActivationID,
		PlanID:         request.Plan.ID,
		RequestedModes: request.Plan.RequestedModes,
		ActiveModes:    []credentialdelivery.Mode{credentialdelivery.ModeEnv},
		Bindings:       resolution.bindings,
		ProofRefs:      resolution.proofs,
		Status:         credentialdelivery.StatusActive,
		ReasonCode:     credentialdelivery.ReasonRequested,
	}), nil
}

type envResolution struct {
	resolved []halfactory.ResolvedRunSecret
	bindings []credentialdelivery.BindingActivationResult
	proofs   []credentialdelivery.ActivationProofReference
	failed   bool
	reason   credentialdelivery.ReasonCode
}

func (a *EnvAdapter) resolve(request credentialdelivery.ActivationRequest) envResolution {
	required := requiredSecretIDs(a.requiredSecretIDs)
	seenSecrets := make(map[string]struct{}, len(request.Bindings))
	resolution := envResolution{
		bindings: make([]credentialdelivery.BindingActivationResult, 0, len(request.Bindings)),
		proofs:   make([]credentialdelivery.ActivationProofReference, 0, len(request.Bindings)),
	}

	for _, binding := range request.Bindings {
		if binding.DeliveryMode != credentialdelivery.ModeEnv {
			resolution.bindings = append(resolution.bindings, credentialdelivery.BindingActivationResult{
				BindingID:    binding.ID,
				DeliveryMode: binding.DeliveryMode,
				Status:       credentialdelivery.StatusSkipped,
				ReasonCode:   credentialdelivery.ReasonActivationUnavailable,
			})
			continue
		}

		secretID, name, ok := envSecretReference(binding.SecretRef)
		if !ok {
			resolution.failed = true
			resolution.reason = credentialdelivery.ReasonMissingSecretReference
			resolution.bindings = append(resolution.bindings, envBindingFailure(binding, credentialdelivery.ReasonMissingSecretReference))
			continue
		}

		if _, ok := seenSecrets[secretID]; !ok {
			value, found := a.environment(name)
			if !found || strings.TrimSpace(value) == "" {
				resolution.failed = true
				resolution.reason = credentialdelivery.ReasonMissingSecretReference
				resolution.bindings = append(resolution.bindings, envBindingFailure(binding, credentialdelivery.ReasonMissingSecretReference))
				continue
			}
			seenSecrets[secretID] = struct{}{}
			resolution.resolved = append(resolution.resolved, halfactory.ResolvedRunSecret{
				Name:     name,
				Source:   halfactory.RunSecretSourceEnv,
				Required: secretRequired(required, secretID),
				Value:    value,
			})
		}

		proofID := envProofID(request.ActivationID, binding.ID)
		resolution.proofs = append(resolution.proofs, credentialdelivery.ActivationProofReference{
			ProofID:      proofID,
			BindingID:    binding.ID,
			DeliveryMode: credentialdelivery.ModeEnv,
		})
		resolution.bindings = append(resolution.bindings, credentialdelivery.BindingActivationResult{
			BindingID:    binding.ID,
			DeliveryMode: credentialdelivery.ModeEnv,
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

func envDisabledResult(request credentialdelivery.ActivationRequest) credentialdelivery.ActivationResult {
	return credentialdelivery.SanitizeActivationResultMetadata(credentialdelivery.ActivationResult{
		ID:             request.ActivationID,
		PlanID:         request.Plan.ID,
		RequestedModes: request.Plan.RequestedModes,
		Bindings:       envBindingResults(request.Bindings, credentialdelivery.StatusDisabled, credentialdelivery.ReasonDisabled),
		Status:         credentialdelivery.StatusDisabled,
		ReasonCode:     credentialdelivery.ReasonDisabled,
	})
}

func envFailedResult(request credentialdelivery.ActivationRequest, reason credentialdelivery.ReasonCode) credentialdelivery.ActivationResult {
	if reason == "" {
		reason = credentialdelivery.ReasonActivationUnavailable
	}
	return credentialdelivery.SanitizeActivationResultMetadata(credentialdelivery.ActivationResult{
		ID:             request.ActivationID,
		PlanID:         request.Plan.ID,
		RequestedModes: request.Plan.RequestedModes,
		Bindings:       envBindingResults(request.Bindings, credentialdelivery.StatusFailed, reason),
		Status:         credentialdelivery.StatusFailed,
		ReasonCode:     reason,
		Warnings:       envActivationWarnings(request.Bindings, reason),
	})
}

func envSkippedResult(request credentialdelivery.ActivationRequest, reason credentialdelivery.ReasonCode) credentialdelivery.ActivationResult {
	if reason == "" {
		reason = credentialdelivery.ReasonActivationUnavailable
	}
	return credentialdelivery.SanitizeActivationResultMetadata(credentialdelivery.ActivationResult{
		ID:             request.ActivationID,
		PlanID:         request.Plan.ID,
		RequestedModes: request.Plan.RequestedModes,
		Bindings:       envBindingResults(request.Bindings, credentialdelivery.StatusSkipped, reason),
		Status:         credentialdelivery.StatusSkipped,
		ReasonCode:     reason,
		Warnings:       envActivationWarnings(request.Bindings, reason),
	})
}

func envBindingResults(bindings []credentialdelivery.Binding, status credentialdelivery.Status, reason credentialdelivery.ReasonCode) []credentialdelivery.BindingActivationResult {
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

func envBindingFailure(binding credentialdelivery.Binding, reason credentialdelivery.ReasonCode) credentialdelivery.BindingActivationResult {
	return credentialdelivery.BindingActivationResult{
		BindingID:    binding.ID,
		DeliveryMode: binding.DeliveryMode,
		Status:       credentialdelivery.StatusFailed,
		ReasonCode:   reason,
	}
}

func envActivationWarnings(bindings []credentialdelivery.Binding, reason credentialdelivery.ReasonCode) []credentialdelivery.Warning {
	if len(bindings) == 0 {
		return nil
	}
	warnings := make([]credentialdelivery.Warning, 0, len(bindings))
	for _, binding := range credentialdelivery.SanitizeBindingMetadataRecords(bindings) {
		if binding.DeliveryMode != credentialdelivery.ModeEnv {
			continue
		}
		warnings = append(warnings, credentialdelivery.Warning{
			Code:       credentialdelivery.WarningActivationSkipped,
			ReasonCode: reason,
			BindingID:  binding.ID,
			Mode:       credentialdelivery.ModeEnv,
		})
	}
	if len(warnings) == 0 {
		return nil
	}
	return warnings
}

func envSecretReference(ref string) (secretID string, name string, ok bool) {
	source, name, ok := strings.Cut(strings.TrimSpace(ref), ":")
	if !ok || source != halfactory.RunSecretSourceEnv || !safeEnvName(name) {
		return "", "", false
	}
	return source + ":" + name, name, true
}

func safeEnvName(name string) bool {
	if name == "" || name != strings.TrimSpace(name) {
		return false
	}
	for i, r := range name {
		switch {
		case r >= 'A' && r <= 'Z':
		case r == '_' && i > 0:
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

func requiredSecretIDs(ids []string) map[string]struct{} {
	if len(ids) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		secretID, _, ok := envSecretReference(id)
		if ok {
			out[secretID] = struct{}{}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func secretRequired(required map[string]struct{}, secretID string) bool {
	if len(required) == 0 {
		return true
	}
	_, ok := required[secretID]
	return ok
}

func envProofID(activationID, bindingID string) string {
	return activationID + "-" + bindingID + "-env-proof"
}
