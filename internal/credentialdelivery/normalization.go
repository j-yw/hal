package credentialdelivery

import (
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
)

// NormalizeRequestMetadata returns a deterministic copy of credential delivery
// request metadata before validation or persistence.
func NormalizeRequestMetadata(request Request) Request {
	return Request{
		ID:             strings.TrimSpace(request.ID),
		Source:         normalizeSource(request.Source),
		RequestedModes: normalizeModeRecords(request.RequestedModes),
		ActiveModes:    normalizeModeRecords(request.ActiveModes),
		Bindings:       NormalizeBindingMetadataRecords(request.Bindings),
		Status:         normalizeStatus(request.Status),
	}
}

// NormalizeBindingMetadata returns a deterministic copy of one credential
// delivery binding before validation or persistence.
func NormalizeBindingMetadata(binding Binding) Binding {
	return Binding{
		ID:                    strings.TrimSpace(binding.ID),
		RequestID:             strings.TrimSpace(binding.RequestID),
		PlanID:                strings.TrimSpace(binding.PlanID),
		PolicySnapshotID:      strings.TrimSpace(binding.PolicySnapshotID),
		SecretRef:             strings.TrimSpace(binding.SecretRef),
		NetworkProxySessionID: strings.TrimSpace(binding.NetworkProxySessionID),
		ServiceID:             strings.TrimSpace(binding.ServiceID),
		ServiceLabels:         normalizeStringRecords(binding.ServiceLabels),
		DomainLabels:          normalizeStringRecords(binding.DomainLabels),
		DestinationCategory:   normalizeDestinationCategory(binding.DestinationCategory),
		DeliveryMode:          normalizeMode(binding.DeliveryMode),
		Status:                normalizeStatus(binding.Status),
		ReasonCode:            normalizeReasonCode(binding.ReasonCode),
	}
}

// NormalizeBindingMetadataRecords returns normalized binding copies while
// preserving nil versus explicit empty slices.
func NormalizeBindingMetadataRecords(bindings []Binding) []Binding {
	if bindings == nil {
		return nil
	}
	normalized := make([]Binding, len(bindings))
	for i, binding := range bindings {
		normalized[i] = NormalizeBindingMetadata(binding)
	}
	return normalized
}

// NormalizeSecretReferenceMetadata returns a deterministic copy of one safe
// broker secret reference before resolver lookup.
func NormalizeSecretReferenceMetadata(reference SecretReference) SecretReference {
	return SecretReference{
		BindingID: strings.TrimSpace(reference.BindingID),
		SecretRef: strings.TrimSpace(reference.SecretRef),
	}
}

// NormalizeBrokerSecretMetadata returns a deterministic copy of broker secret
// metadata before validation or persistence.
func NormalizeBrokerSecretMetadata(metadata BrokerSecretMetadata) BrokerSecretMetadata {
	return BrokerSecretMetadata{
		ID:       strings.TrimSpace(metadata.ID),
		Source:   strings.TrimSpace(metadata.Source),
		Required: metadata.Required,
		Present:  metadata.Present,
	}
}

// NormalizeResolvedBindingSecretMetadata returns a deterministic copy of one
// resolved binding record before validation or persistence.
func NormalizeResolvedBindingSecretMetadata(resolved ResolvedBindingSecretMetadata) ResolvedBindingSecretMetadata {
	return ResolvedBindingSecretMetadata{
		BindingID:    strings.TrimSpace(resolved.BindingID),
		SecretRef:    strings.TrimSpace(resolved.SecretRef),
		DeliveryMode: normalizeMode(resolved.DeliveryMode),
		BrokerSecret: NormalizeBrokerSecretMetadata(resolved.BrokerSecret),
	}
}

// NormalizeResolvedBindingSecretMetadataRecords returns normalized resolution
// records while preserving nil versus explicit empty slices.
func NormalizeResolvedBindingSecretMetadataRecords(records []ResolvedBindingSecretMetadata) []ResolvedBindingSecretMetadata {
	if records == nil {
		return nil
	}
	normalized := make([]ResolvedBindingSecretMetadata, len(records))
	for i, record := range records {
		normalized[i] = NormalizeResolvedBindingSecretMetadata(record)
	}
	return normalized
}

// NormalizeSecretResolutionResult returns a deterministic copy of resolver
// output before durable persistence.
func NormalizeSecretResolutionResult(result SecretResolutionResult) SecretResolutionResult {
	return SecretResolutionResult{
		Valid:    result.Valid,
		Bindings: NormalizeResolvedBindingSecretMetadataRecords(result.Bindings),
		Warnings: NormalizeWarningMetadataRecords(result.Warnings),
		Errors:   NormalizeSanitizedErrorRecords(result.Errors),
	}
}

// NormalizePlanMetadata returns a deterministic copy of a durable delivery
// plan summary before validation or persistence.
func NormalizePlanMetadata(plan Plan) Plan {
	return Plan{
		ID:                    strings.TrimSpace(plan.ID),
		RequestID:             strings.TrimSpace(plan.RequestID),
		NetworkProxySessionID: strings.TrimSpace(plan.NetworkProxySessionID),
		HTTPProxyProof:        NormalizeHTTPProxyProofMetadataPtr(plan.HTTPProxyProof),
		RequestedModes:        normalizeModeRecords(plan.RequestedModes),
		ActiveModes:           normalizeModeRecords(plan.ActiveModes),
		BindingCount:          plan.BindingCount,
		Status:                normalizeStatus(plan.Status),
		Warnings:              NormalizeWarningMetadataRecords(plan.Warnings),
		Errors:                NormalizeSanitizedErrorRecords(plan.Errors),
	}
}

// NormalizeHTTPProxyProofMetadata returns a deterministic copy of safe
// http_proxy activation proof metadata before validation or persistence.
func NormalizeHTTPProxyProofMetadata(proof HTTPProxyProof) HTTPProxyProof {
	normalized := HTTPProxyProof{
		BindingID:                strings.TrimSpace(proof.BindingID),
		SecretID:                 strings.TrimSpace(proof.SecretID),
		SecretBrokerSessionID:    strings.TrimSpace(proof.SecretBrokerSessionID),
		CredentialProxyPlanID:    strings.TrimSpace(proof.CredentialProxyPlanID),
		CredentialProxySessionID: strings.TrimSpace(proof.CredentialProxySessionID),
		CredentialProxyBindingID: strings.TrimSpace(proof.CredentialProxyBindingID),
	}
	if proof.NetworkEnforcement != nil {
		network := sandbox.SanitizeSandboxNetworkEnforcementProofMetadata(*proof.NetworkEnforcement)
		normalized.NetworkEnforcement = &network
	}
	return normalized
}

// NormalizeHTTPProxyProofMetadataPtr returns a normalized pointer copy while
// preserving nil inputs.
func NormalizeHTTPProxyProofMetadataPtr(proof *HTTPProxyProof) *HTTPProxyProof {
	if proof == nil {
		return nil
	}
	normalized := NormalizeHTTPProxyProofMetadata(*proof)
	return &normalized
}

// NormalizeActivationResultMetadata returns a deterministic copy of durable
// activation result metadata before validation or persistence.
func NormalizeActivationResultMetadata(result ActivationResult) ActivationResult {
	return ActivationResult{
		ID:             strings.TrimSpace(result.ID),
		PlanID:         strings.TrimSpace(result.PlanID),
		RequestedModes: normalizeModeRecords(result.RequestedModes),
		ActiveModes:    normalizeModeRecords(result.ActiveModes),
		Bindings:       NormalizeBindingActivationResultMetadataRecords(result.Bindings),
		ProofRefs:      NormalizeActivationProofReferenceMetadataRecords(result.ProofRefs),
		Status:         normalizeStatus(result.Status),
		ReasonCode:     normalizeReasonCode(result.ReasonCode),
		Warnings:       NormalizeWarningMetadataRecords(result.Warnings),
	}
}

// NormalizeBindingActivationResultMetadata returns a deterministic copy of one
// binding activation result before validation or persistence.
func NormalizeBindingActivationResultMetadata(result BindingActivationResult) BindingActivationResult {
	return BindingActivationResult{
		BindingID:    strings.TrimSpace(result.BindingID),
		DeliveryMode: normalizeMode(result.DeliveryMode),
		Status:       normalizeStatus(result.Status),
		ReasonCode:   normalizeReasonCode(result.ReasonCode),
		ProofRef:     strings.TrimSpace(result.ProofRef),
	}
}

// NormalizeBindingActivationResultMetadataRecords returns normalized binding
// activation copies while preserving nil versus explicit empty slices.
func NormalizeBindingActivationResultMetadataRecords(results []BindingActivationResult) []BindingActivationResult {
	if results == nil {
		return nil
	}
	normalized := make([]BindingActivationResult, len(results))
	for i, result := range results {
		normalized[i] = NormalizeBindingActivationResultMetadata(result)
	}
	return normalized
}

// NormalizeActivationProofReferenceMetadata returns a deterministic copy of one
// activation proof reference before validation or persistence.
func NormalizeActivationProofReferenceMetadata(reference ActivationProofReference) ActivationProofReference {
	return ActivationProofReference{
		ProofID:      strings.TrimSpace(reference.ProofID),
		BindingID:    strings.TrimSpace(reference.BindingID),
		DeliveryMode: normalizeMode(reference.DeliveryMode),
	}
}

// NormalizeActivationProofReferenceMetadataRecords returns normalized proof
// references while preserving nil versus explicit empty slices.
func NormalizeActivationProofReferenceMetadataRecords(references []ActivationProofReference) []ActivationProofReference {
	if references == nil {
		return nil
	}
	normalized := make([]ActivationProofReference, len(references))
	for i, reference := range references {
		normalized[i] = NormalizeActivationProofReferenceMetadata(reference)
	}
	return normalized
}

// NormalizeStatusMetadata returns a deterministic copy of compact delivery
// lifecycle status metadata before validation or persistence.
func NormalizeStatusMetadata(status StatusMetadata) StatusMetadata {
	return StatusMetadata{
		ID:             strings.TrimSpace(status.ID),
		RequestID:      strings.TrimSpace(status.RequestID),
		PlanID:         strings.TrimSpace(status.PlanID),
		ActivationID:   strings.TrimSpace(status.ActivationID),
		RequestedModes: normalizeModeRecords(status.RequestedModes),
		ActiveModes:    normalizeModeRecords(status.ActiveModes),
		Status:         normalizeStatus(status.Status),
		ReasonCode:     normalizeReasonCode(status.ReasonCode),
		WarningCount:   status.WarningCount,
		ErrorCount:     status.ErrorCount,
	}
}

// NormalizeWarningMetadata returns a deterministic copy of redaction-safe
// warning metadata before validation or persistence.
func NormalizeWarningMetadata(warning Warning) Warning {
	return Warning{
		Code:       normalizeWarningCode(warning.Code),
		ReasonCode: normalizeReasonCode(warning.ReasonCode),
		BindingID:  strings.TrimSpace(warning.BindingID),
		Mode:       normalizeMode(warning.Mode),
	}
}

// NormalizeWarningMetadataRecords returns normalized warning copies while
// preserving nil versus explicit empty slices.
func NormalizeWarningMetadataRecords(warnings []Warning) []Warning {
	if warnings == nil {
		return nil
	}
	normalized := make([]Warning, len(warnings))
	for i, warning := range warnings {
		normalized[i] = NormalizeWarningMetadata(warning)
	}
	return normalized
}

// NormalizeSanitizedError returns a deterministic copy of redaction-safe error
// metadata before validation or persistence.
func NormalizeSanitizedError(err SanitizedError) SanitizedError {
	normalized := SanitizedError{
		Code:       normalizeErrorCode(err.Code),
		Field:      strings.TrimSpace(err.Field),
		BindingID:  strings.TrimSpace(err.BindingID),
		Mode:       normalizeMode(err.Mode),
		ReasonCode: normalizeReasonCode(err.ReasonCode),
	}
	if err.Index != nil {
		index := *err.Index
		normalized.Index = &index
	}
	return normalized
}

// NormalizeSanitizedErrorRecords returns normalized error copies while
// preserving nil versus explicit empty slices.
func NormalizeSanitizedErrorRecords(errors []SanitizedError) []SanitizedError {
	if errors == nil {
		return nil
	}
	normalized := make([]SanitizedError, len(errors))
	for i, err := range errors {
		normalized[i] = NormalizeSanitizedError(err)
	}
	return normalized
}

// NormalizeValidationResult returns a deterministic copy of validation output
// before durable persistence.
func NormalizeValidationResult(result ValidationResult) ValidationResult {
	return ValidationResult{
		Valid:  result.Valid,
		Errors: NormalizeSanitizedErrorRecords(result.Errors),
	}
}

func normalizeStringRecords(values []string) []string {
	if values == nil {
		return nil
	}
	normalized := make([]string, len(values))
	for i, value := range values {
		normalized[i] = strings.TrimSpace(value)
	}
	return normalized
}

func normalizeModeRecords(values []Mode) []Mode {
	if values == nil {
		return nil
	}
	normalized := make([]Mode, len(values))
	for i, value := range values {
		normalized[i] = normalizeMode(value)
	}
	return normalized
}

func normalizeMode(mode Mode) Mode {
	return Mode(strings.ToLower(strings.TrimSpace(string(mode))))
}

func normalizeDestinationCategory(category DestinationCategory) DestinationCategory {
	return DestinationCategory(strings.ToLower(strings.TrimSpace(string(category))))
}

func normalizeSource(source Source) Source {
	return Source(strings.ToLower(strings.TrimSpace(string(source))))
}

func normalizeStatus(status Status) Status {
	return Status(strings.ToLower(strings.TrimSpace(string(status))))
}

func normalizeReasonCode(reason ReasonCode) ReasonCode {
	return ReasonCode(strings.ToLower(strings.TrimSpace(string(reason))))
}

func normalizeWarningCode(warning WarningCode) WarningCode {
	return WarningCode(strings.ToLower(strings.TrimSpace(string(warning))))
}

func normalizeErrorCode(code ErrorCode) ErrorCode {
	return ErrorCode(strings.ToLower(strings.TrimSpace(string(code))))
}
