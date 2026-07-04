package sandbox

import "strings"

// SandboxCredentialDeliveryStatusMetadata is a compact credential delivery
// lifecycle summary for durable sandbox and factory surfaces. It carries only
// safe identifiers, mode labels, status labels, and counts.
type SandboxCredentialDeliveryStatusMetadata struct {
	ID             string                                  `json:"id"`
	RequestID      string                                  `json:"requestId,omitempty"`
	PlanID         string                                  `json:"planId,omitempty"`
	ActivationID   string                                  `json:"activationId,omitempty"`
	RequestedModes []string                                `json:"requestedModes,omitempty"`
	ActiveModes    []string                                `json:"activeModes,omitempty"`
	ActiveProofs   []SandboxCredentialDeliveryProofSummary `json:"activeProofs,omitempty"`
	Status         string                                  `json:"status,omitempty"`
	ReasonCode     string                                  `json:"reasonCode,omitempty"`
	WarningCount   int                                     `json:"warningCount,omitempty"`
	ErrorCount     int                                     `json:"errorCount,omitempty"`
}

// SandboxCredentialDeliveryProofSummary is the readiness-consumable active
// proof shape for brokered credential delivery. It carries only safe proof and
// binding identifiers plus enum-like mode/status/source labels.
type SandboxCredentialDeliveryProofSummary struct {
	ProofID      string `json:"proofId"`
	BindingID    string `json:"bindingId,omitempty"`
	DeliveryMode string `json:"deliveryMode"`
	Status       string `json:"status,omitempty"`
	Source       string `json:"source,omitempty"`
}

// SandboxCredentialDeliveryStatusProjectionRequest describes safe command or
// factory inputs for projecting plan-only credential delivery status metadata.
type SandboxCredentialDeliveryStatusProjectionRequest struct {
	Plan                  *SandboxCredentialProxyPlanMetadata
	Bindings              []SandboxCredentialProxyBindingMetadata
	RequestedModes        []string
	CompatibilityAuthSync bool
}

// ProjectSandboxCredentialDeliveryStatusMetadata derives a durable-safe,
// plan-only credential delivery summary from credential proxy metadata.
func ProjectSandboxCredentialDeliveryStatusMetadata(req SandboxCredentialDeliveryStatusProjectionRequest) *SandboxCredentialDeliveryStatusMetadata {
	if req.Plan == nil {
		return nil
	}
	plan := SanitizeSandboxCredentialProxyPlanMetadata(*req.Plan)
	if plan.ID == "" {
		return nil
	}
	requestedModes := normalizeSandboxSecretModes(req.RequestedModes)
	if req.CompatibilityAuthSync {
		requestedModes = appendSandboxSecretMode(requestedModes, SandboxSecretModeLegacyAuthSync)
	}
	if len(requestedModes) == 0 && len(req.Bindings) > 0 {
		requestedModes = sandboxCredentialDeliveryModesFromCredentialProxyBindings(req.Bindings)
	}
	status := sandboxCredentialDeliveryStatusFromCredentialProxyStatus(plan.Status)
	if status == "" {
		status = "planned"
	}
	sanitized := SanitizeSandboxCredentialDeliveryStatusMetadata(SandboxCredentialDeliveryStatusMetadata{
		ID:             plan.ID,
		PlanID:         plan.ID,
		RequestedModes: requestedModes,
		Status:         status,
	})
	if sanitized.ID == "" {
		return nil
	}
	return &sanitized
}

// SanitizeSandboxCredentialDeliveryStatusMetadata returns a durable-safe copy
// of compact credential delivery metadata.
func SanitizeSandboxCredentialDeliveryStatusMetadata(status SandboxCredentialDeliveryStatusMetadata) SandboxCredentialDeliveryStatusMetadata {
	sanitizedStatus := sanitizeSandboxCredentialDeliveryStatus(status.Status)
	sanitized := SandboxCredentialDeliveryStatusMetadata{
		ID:             sanitizeSandboxCredentialDeliveryIdentifier(status.ID),
		RequestID:      sanitizeSandboxCredentialDeliveryIdentifier(status.RequestID),
		PlanID:         sanitizeSandboxCredentialDeliveryIdentifier(status.PlanID),
		ActivationID:   sanitizeSandboxCredentialDeliveryIdentifier(status.ActivationID),
		RequestedModes: normalizeSandboxSecretModes(status.RequestedModes),
		ActiveModes:    normalizeSandboxSecretModes(status.ActiveModes),
		Status:         sanitizedStatus,
		ReasonCode:     sanitizeSandboxCredentialDeliveryReasonCode(status.ReasonCode),
		WarningCount:   nonNegativeCredentialDeliveryCount(status.WarningCount),
		ErrorCount:     nonNegativeCredentialDeliveryCount(status.ErrorCount),
	}
	if sanitized.ID == "" {
		return SandboxCredentialDeliveryStatusMetadata{}
	}
	if sanitizedStatus == "active" && sanitized.ActivationID != "" {
		sanitized.ActiveProofs = sanitizeSandboxCredentialDeliveryProofSummaries(status.ActiveProofs)
		sanitized.ActiveModes = mergeSandboxCredentialDeliveryActiveProofModes(sanitized.ActiveModes, sanitized.ActiveProofs)
	}
	return sanitized
}

// SanitizeSandboxCredentialDeliverySurfaceStatusMetadata returns the command
// and factory-safe credential delivery status shape. Active secure-default
// delivery is exposed only when sanitized active proof summaries exist.
func SanitizeSandboxCredentialDeliverySurfaceStatusMetadata(status SandboxCredentialDeliveryStatusMetadata) SandboxCredentialDeliveryStatusMetadata {
	sanitized := SanitizeSandboxCredentialDeliveryStatusMetadata(status)
	if sanitized.ID == "" {
		return SandboxCredentialDeliveryStatusMetadata{}
	}
	if sanitized.Status == "active" && sanitized.ActivationID != "" && len(sanitized.ActiveProofs) > 0 {
		sanitized.ActiveModes = sandboxCredentialDeliveryProofModes(sanitized.ActiveProofs)
		return sanitized
	}
	sanitized.ActiveModes = nil
	sanitized.ActiveProofs = nil
	if sanitized.Status == "active" {
		sanitized.Status = "skipped"
		if sanitized.ReasonCode == "" || sanitized.ReasonCode == "requested" {
			sanitized.ReasonCode = "missing_activation_proof"
		}
	}
	return sanitized
}

func sanitizeSandboxCredentialDeliveryIdentifier(value string) string {
	trimmed := strings.TrimSpace(value)
	if sandboxCredentialDeliveryIdentifierLooksUnsafe(trimmed) {
		return ""
	}
	sanitized := sanitizeSandboxCredentialProxyIdentifier(trimmed)
	if sandboxCredentialDeliveryIdentifierLooksUnsafe(sanitized) {
		return ""
	}
	return sanitized
}

func sandboxCredentialDeliveryIdentifierLooksUnsafe(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" {
		return false
	}
	if strings.HasPrefix(lower, "sk-") ||
		strings.HasPrefix(lower, "ghp_") ||
		strings.HasPrefix(lower, "github_pat_") {
		return true
	}
	for _, marker := range []string{"/", "\\", ":", "=", "@", "://", ".invalid", ".com", ".net", ".org", "authorization", "bearer"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func sanitizeSandboxCredentialDeliveryStatus(status string) string {
	switch strings.TrimSpace(strings.ToLower(status)) {
	case "requested", "planned", "ready", "active", "completed", "skipped", "failed", "disabled":
		return strings.TrimSpace(strings.ToLower(status))
	default:
		return ""
	}
}

func sanitizeSandboxCredentialDeliveryProofSummaries(values []SandboxCredentialDeliveryProofSummary) []SandboxCredentialDeliveryProofSummary {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]SandboxCredentialDeliveryProofSummary, 0, len(values))
	for _, value := range values {
		proof := sanitizeSandboxCredentialDeliveryProofSummary(value)
		if proof.ProofID == "" {
			continue
		}
		key := proof.ProofID + "\x00" + proof.BindingID + "\x00" + proof.DeliveryMode
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, proof)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sanitizeSandboxCredentialDeliveryProofSummary(proof SandboxCredentialDeliveryProofSummary) SandboxCredentialDeliveryProofSummary {
	mode := sanitizeSandboxCredentialDeliveryProofMode(proof.DeliveryMode)
	if mode == "" {
		return SandboxCredentialDeliveryProofSummary{}
	}
	status := sanitizeSandboxCredentialDeliveryStatus(proof.Status)
	if status != "active" {
		return SandboxCredentialDeliveryProofSummary{}
	}
	proofID := sanitizeSandboxCredentialDeliveryIdentifier(proof.ProofID)
	if proofID == "" {
		return SandboxCredentialDeliveryProofSummary{}
	}
	originalBindingID := strings.TrimSpace(proof.BindingID)
	bindingID := sanitizeSandboxCredentialDeliveryIdentifier(originalBindingID)
	if originalBindingID != "" && bindingID == "" {
		return SandboxCredentialDeliveryProofSummary{}
	}
	originalSource := strings.TrimSpace(proof.Source)
	source := sanitizeSandboxCredentialDeliveryProofSource(originalSource)
	if originalSource != "" && source == "" {
		return SandboxCredentialDeliveryProofSummary{}
	}
	return SandboxCredentialDeliveryProofSummary{
		ProofID:      proofID,
		BindingID:    bindingID,
		DeliveryMode: mode,
		Status:       status,
		Source:       source,
	}
}

func sanitizeSandboxCredentialDeliveryProofMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case SandboxSecretModeHTTPProxy, SandboxSecretModeSSHAgent, SandboxSecretModeFileTmpfs:
		return strings.ToLower(strings.TrimSpace(mode))
	default:
		return ""
	}
}

func sanitizeSandboxCredentialDeliveryProofSource(source string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "broker", "secret_broker", "credential_proxy", "network_proxy", "handoff", "simulation", "adapter", "runtime", "worker":
		return strings.ToLower(strings.TrimSpace(source))
	default:
		return ""
	}
}

func mergeSandboxCredentialDeliveryActiveProofModes(modes []string, proofs []SandboxCredentialDeliveryProofSummary) []string {
	if len(proofs) == 0 {
		return modes
	}
	out := append([]string(nil), modes...)
	for _, proof := range proofs {
		out = appendSandboxSecretMode(out, proof.DeliveryMode)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sandboxCredentialDeliveryProofModes(proofs []SandboxCredentialDeliveryProofSummary) []string {
	if len(proofs) == 0 {
		return nil
	}
	var out []string
	for _, proof := range proofs {
		out = appendSandboxSecretMode(out, proof.DeliveryMode)
	}
	return out
}

func sanitizeSandboxCredentialDeliveryReasonCode(reason string) string {
	switch strings.TrimSpace(strings.ToLower(reason)) {
	case "requested",
		"unsupported_mode",
		"missing_secret_reference",
		"missing_service_binding",
		"missing_activation_proof",
		"unsupported_capability",
		"activation_unavailable",
		"compatibility_mode",
		"disabled",
		"unknown":
		return strings.TrimSpace(strings.ToLower(reason))
	default:
		return ""
	}
}

func nonNegativeCredentialDeliveryCount(value int) int {
	if value < 0 {
		return 0
	}
	return value
}

func sandboxCredentialDeliveryModesFromCredentialProxyBindings(bindings []SandboxCredentialProxyBindingMetadata) []string {
	if len(bindings) == 0 {
		return nil
	}
	var out []string
	for _, binding := range SanitizeSandboxCredentialProxyBindingMetadataRecords(bindings) {
		out = appendSandboxSecretMode(out, string(binding.DeliveryMode))
	}
	return out
}

func sandboxCredentialDeliveryStatusFromCredentialProxyStatus(status SandboxCredentialProxyStatus) string {
	switch SandboxCredentialProxyStatus(strings.TrimSpace(strings.ToLower(string(status)))) {
	case SandboxCredentialProxyStatusPlanned:
		return "planned"
	case SandboxCredentialProxyStatusReady:
		return "ready"
	case SandboxCredentialProxyStatusActive:
		return "ready"
	case SandboxCredentialProxyStatusCompleted:
		return "completed"
	case SandboxCredentialProxyStatusSkipped:
		return "skipped"
	case SandboxCredentialProxyStatusFailed:
		return "failed"
	case SandboxCredentialProxyStatusDisabled:
		return "disabled"
	default:
		return ""
	}
}
