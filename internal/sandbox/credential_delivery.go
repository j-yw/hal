package sandbox

import "strings"

// SandboxCredentialDeliveryStatusMetadata is a compact credential delivery
// lifecycle summary for durable sandbox and factory surfaces. It carries only
// safe identifiers, mode labels, status labels, and counts.
type SandboxCredentialDeliveryStatusMetadata struct {
	ID             string   `json:"id"`
	RequestID      string   `json:"requestId,omitempty"`
	PlanID         string   `json:"planId,omitempty"`
	ActivationID   string   `json:"activationId,omitempty"`
	RequestedModes []string `json:"requestedModes,omitempty"`
	ActiveModes    []string `json:"activeModes,omitempty"`
	Status         string   `json:"status,omitempty"`
	ReasonCode     string   `json:"reasonCode,omitempty"`
	WarningCount   int      `json:"warningCount,omitempty"`
	ErrorCount     int      `json:"errorCount,omitempty"`
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
	sanitized := SandboxCredentialDeliveryStatusMetadata{
		ID:             sanitizeSandboxCredentialDeliveryIdentifier(status.ID),
		RequestID:      sanitizeSandboxCredentialDeliveryIdentifier(status.RequestID),
		PlanID:         sanitizeSandboxCredentialDeliveryIdentifier(status.PlanID),
		ActivationID:   sanitizeSandboxCredentialDeliveryIdentifier(status.ActivationID),
		RequestedModes: normalizeSandboxSecretModes(status.RequestedModes),
		ActiveModes:    normalizeSandboxSecretModes(status.ActiveModes),
		Status:         sanitizeSandboxCredentialDeliveryStatus(status.Status),
		ReasonCode:     sanitizeSandboxCredentialDeliveryReasonCode(status.ReasonCode),
		WarningCount:   nonNegativeCredentialDeliveryCount(status.WarningCount),
		ErrorCount:     nonNegativeCredentialDeliveryCount(status.ErrorCount),
	}
	if sanitized.ID == "" {
		return SandboxCredentialDeliveryStatusMetadata{}
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

func sanitizeSandboxCredentialDeliveryReasonCode(reason string) string {
	switch strings.TrimSpace(strings.ToLower(reason)) {
	case "requested",
		"unsupported_mode",
		"missing_secret_reference",
		"missing_service_binding",
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
