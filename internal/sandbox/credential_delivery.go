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

// SanitizeSandboxCredentialDeliveryStatusMetadata returns a durable-safe copy
// of compact credential delivery metadata.
func SanitizeSandboxCredentialDeliveryStatusMetadata(status SandboxCredentialDeliveryStatusMetadata) SandboxCredentialDeliveryStatusMetadata {
	sanitized := SandboxCredentialDeliveryStatusMetadata{
		ID:             sanitizeSandboxCredentialProxyIdentifier(strings.TrimSpace(status.ID)),
		RequestID:      sanitizeSandboxCredentialProxyIdentifier(strings.TrimSpace(status.RequestID)),
		PlanID:         sanitizeSandboxCredentialProxyIdentifier(strings.TrimSpace(status.PlanID)),
		ActivationID:   sanitizeSandboxCredentialProxyIdentifier(strings.TrimSpace(status.ActivationID)),
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
