package sandboxruntime

import (
	"encoding/json"
	"strings"
)

// SanitizeRuntimeCredentialDeliveryMetadata preserves only compact,
// redaction-safe credential delivery status labels for runtime and worker
// protocol surfaces.
func SanitizeRuntimeCredentialDeliveryMetadata(metadata *RuntimeCredentialDeliveryMetadata) *RuntimeCredentialDeliveryMetadata {
	if metadata == nil {
		return nil
	}
	status := sanitizeRuntimeCredentialDeliveryStatus(metadata.Status)
	sanitized := &RuntimeCredentialDeliveryMetadata{
		ID:             sanitizeRuntimeCredentialDeliveryID(metadata.ID),
		RequestID:      sanitizeRuntimeCredentialDeliveryID(metadata.RequestID),
		PlanID:         sanitizeRuntimeCredentialDeliveryID(metadata.PlanID),
		ActivationID:   sanitizeRuntimeCredentialDeliveryID(metadata.ActivationID),
		RequestedModes: sanitizeRuntimeCredentialDeliveryModeList(metadata.RequestedModes, true),
		Status:         status,
		ReasonCode:     sanitizeRuntimeCredentialDeliveryReason(metadata.ReasonCode),
		WarningCount:   sanitizeRuntimeCredentialDeliveryCount(metadata.WarningCount),
		ErrorCount:     sanitizeRuntimeCredentialDeliveryCount(metadata.ErrorCount),
	}
	if sanitized.ID == "" {
		return nil
	}
	if status == "active" && sanitized.ActivationID != "" {
		sanitized.ActiveModes = sanitizeRuntimeCredentialDeliveryModeList(metadata.ActiveModes, false)
	}
	if status == "active" && len(sanitized.ActiveModes) == 0 {
		sanitized.Status = "skipped"
	}
	return sanitized
}

func (metadata RuntimeCredentialDeliveryMetadata) MarshalJSON() ([]byte, error) {
	type runtimeCredentialDeliveryMetadataJSON RuntimeCredentialDeliveryMetadata
	sanitized := SanitizeRuntimeCredentialDeliveryMetadata(&metadata)
	if sanitized == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(runtimeCredentialDeliveryMetadataJSON(*sanitized))
}

func (metadata *RuntimeCredentialDeliveryMetadata) UnmarshalJSON(data []byte) error {
	type runtimeCredentialDeliveryMetadataJSON RuntimeCredentialDeliveryMetadata
	var decoded runtimeCredentialDeliveryMetadataJSON
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	sanitized := SanitizeRuntimeCredentialDeliveryMetadata((*RuntimeCredentialDeliveryMetadata)(&decoded))
	if sanitized == nil {
		*metadata = RuntimeCredentialDeliveryMetadata{}
		return nil
	}
	*metadata = *sanitized
	return nil
}

func sanitizeRuntimeCredentialDeliveryModeList(values []string, includeCompatibility bool) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		mode := sanitizeRuntimeCredentialDeliveryMode(value)
		if mode == "" || (!includeCompatibility && mode == "legacy_auth_sync") || seen[mode] {
			continue
		}
		seen[mode] = true
		out = append(out, mode)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sanitizeRuntimeCredentialDeliveryMode(value string) string {
	switch normalizeRuntimeCredentialDeliveryEnum(value) {
	case "http_proxy", "ssh_agent", "file_tmpfs", "env", "legacy_auth_sync":
		return normalizeRuntimeCredentialDeliveryEnum(value)
	default:
		return ""
	}
}

func sanitizeRuntimeCredentialDeliveryStatus(value string) string {
	switch normalizeRuntimeCredentialDeliveryEnum(value) {
	case "requested", "planned", "ready", "active", "completed", "skipped", "failed", "disabled":
		return normalizeRuntimeCredentialDeliveryEnum(value)
	default:
		return ""
	}
}

func sanitizeRuntimeCredentialDeliveryReason(value string) string {
	switch normalizeRuntimeCredentialDeliveryEnum(value) {
	case "requested", "unsupported_mode", "missing_secret_reference", "missing_service_binding", "missing_activation_proof", "unsupported_capability", "activation_unavailable", "compatibility_mode", "disabled", "unknown":
		return normalizeRuntimeCredentialDeliveryEnum(value)
	default:
		return ""
	}
}

func sanitizeRuntimeCredentialDeliveryCount(value int) int {
	if value < 0 {
		return 0
	}
	return value
}

func normalizeRuntimeCredentialDeliveryEnum(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func sanitizeRuntimeCredentialDeliveryID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 || runtimeCredentialDeliveryUnsafeFreeform(value) {
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
	return value
}

func runtimeCredentialDeliveryUnsafeFreeform(value string) bool {
	if value != strings.TrimSpace(value) || runtimeCredentialDeliveryContainsControl(value) || runtimeCredentialDeliveryAllDigits(value) {
		return true
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"://",
		"authorization",
		"proxy-authorization",
		"bearer",
		"cookie",
		"set-cookie",
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
	return strings.ContainsAny(value, "/\\?#\"'`{}[]()<>|;&=$:@")
}

func runtimeCredentialDeliveryContainsControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func runtimeCredentialDeliveryAllDigits(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return value != ""
}
