package sandboxruntime

import (
	"encoding/json"
	"strings"
)

// SanitizeRuntimeNetworkEnforcementMetadata preserves only redaction-safe
// network enforcement plan/result labels.
func SanitizeRuntimeNetworkEnforcementMetadata(metadata *RuntimeNetworkEnforcementMetadata) *RuntimeNetworkEnforcementMetadata {
	if metadata == nil {
		return nil
	}
	sanitized := &RuntimeNetworkEnforcementMetadata{
		Plan:   sanitizeRuntimeNetworkEnforcementPlanMetadata(metadata.Plan),
		Result: sanitizeRuntimeNetworkEnforcementResultMetadata(metadata.Result),
	}
	if sanitized.Plan == nil && sanitized.Result == nil {
		return nil
	}
	return sanitized
}

// SanitizeRuntimeNetworkEnforcementCapability preserves only supported,
// redaction-safe policy-shape capability labels.
func SanitizeRuntimeNetworkEnforcementCapability(capability *RuntimeNetworkEnforcementCapability) *RuntimeNetworkEnforcementCapability {
	if capability == nil || !capability.Supported {
		return nil
	}
	sanitized := &RuntimeNetworkEnforcementCapability{
		Supported:                  true,
		Modes:                      sanitizeRuntimeNetworkEnforcementModeList(capability.Modes),
		SupportsDomainRules:        capability.SupportsDomainRules,
		SupportsEndpointRules:      capability.SupportsEndpointRules,
		SupportsPrivateRangeRules:  capability.SupportsPrivateRangeRules,
		SupportsMetadataEndpoint:   capability.SupportsMetadataEndpoint,
		SupportsLoopbackRules:      capability.SupportsLoopbackRules,
		SupportsLinkLocalRules:     capability.SupportsLinkLocalRules,
		SupportsDefaultDenyPosture: capability.SupportsDefaultDenyPosture,
	}
	if len(sanitized.Modes) == 0 &&
		!sanitized.SupportsDomainRules &&
		!sanitized.SupportsEndpointRules &&
		!sanitized.SupportsPrivateRangeRules &&
		!sanitized.SupportsMetadataEndpoint &&
		!sanitized.SupportsLoopbackRules &&
		!sanitized.SupportsLinkLocalRules &&
		!sanitized.SupportsDefaultDenyPosture {
		return nil
	}
	return sanitized
}

func (metadata RuntimeNetworkEnforcementMetadata) MarshalJSON() ([]byte, error) {
	type runtimeNetworkEnforcementMetadataJSON RuntimeNetworkEnforcementMetadata
	sanitized := SanitizeRuntimeNetworkEnforcementMetadata(&metadata)
	if sanitized == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(runtimeNetworkEnforcementMetadataJSON(*sanitized))
}

func (metadata RuntimeNetworkEnforcementPlanMetadata) MarshalJSON() ([]byte, error) {
	type runtimeNetworkEnforcementPlanMetadataJSON RuntimeNetworkEnforcementPlanMetadata
	sanitized := sanitizeRuntimeNetworkEnforcementPlanMetadata(&metadata)
	if sanitized == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(runtimeNetworkEnforcementPlanMetadataJSON(*sanitized))
}

func (metadata RuntimeNetworkEnforcementResultMetadata) MarshalJSON() ([]byte, error) {
	type runtimeNetworkEnforcementResultMetadataJSON RuntimeNetworkEnforcementResultMetadata
	sanitized := sanitizeRuntimeNetworkEnforcementResultMetadata(&metadata)
	if sanitized == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(runtimeNetworkEnforcementResultMetadataJSON(*sanitized))
}

func (capability RuntimeNetworkEnforcementCapability) MarshalJSON() ([]byte, error) {
	type runtimeNetworkEnforcementCapabilityJSON RuntimeNetworkEnforcementCapability
	sanitized := SanitizeRuntimeNetworkEnforcementCapability(&capability)
	if sanitized == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(runtimeNetworkEnforcementCapabilityJSON(*sanitized))
}

func sanitizeRuntimeNetworkEnforcementPlanMetadata(metadata *RuntimeNetworkEnforcementPlanMetadata) *RuntimeNetworkEnforcementPlanMetadata {
	if metadata == nil {
		return nil
	}
	sanitized := &RuntimeNetworkEnforcementPlanMetadata{
		ID:               sanitizeRuntimeNetworkEnforcementID(metadata.ID),
		Source:           sanitizeRuntimeNetworkEnforcementSource(metadata.Source),
		Operation:        sanitizeRuntimeNetworkEnforcementID(metadata.Operation),
		PolicySnapshotID: sanitizeRuntimeNetworkEnforcementID(metadata.PolicySnapshotID),
		PolicyPreset:     sanitizeRuntimeNetworkEnforcementPolicyPreset(metadata.PolicyPreset),
		DefaultPosture:   sanitizeRuntimeNetworkEnforcementDefaultPosture(metadata.DefaultPosture),
		Mechanisms:       sanitizeRuntimeNetworkEnforcementMechanismList(metadata.Mechanisms),
		Operations:       sanitizeRuntimeNetworkEnforcementIDList(metadata.Operations),
	}
	if sanitized.ID == "" &&
		sanitized.Source == "" &&
		sanitized.Operation == "" &&
		sanitized.PolicySnapshotID == "" &&
		sanitized.PolicyPreset == "" &&
		sanitized.DefaultPosture == "" &&
		len(sanitized.Mechanisms) == 0 &&
		len(sanitized.Operations) == 0 {
		return nil
	}
	return sanitized
}

func sanitizeRuntimeNetworkEnforcementResultMetadata(metadata *RuntimeNetworkEnforcementResultMetadata) *RuntimeNetworkEnforcementResultMetadata {
	if metadata == nil {
		return nil
	}
	outcome := sanitizeRuntimeNetworkEnforcementOutcome(metadata.Outcome)
	mode := sanitizeRuntimeNetworkEnforcementMode(metadata.EnforcementMode)
	if outcome == "" && runtimeNetworkEnforcementModeCanEnforce(mode) {
		outcome = "success"
	}
	if outcome == "" && mode == "best_effort" {
		outcome = "best_effort"
	}
	if outcome == "failure" || outcome == "unsupported" {
		mode = "none"
	}
	if outcome == "best_effort" {
		mode = "best_effort"
	}
	if outcome == "success" && !runtimeNetworkEnforcementModeCanEnforce(mode) {
		mode = "none"
	}
	reason := sanitizeRuntimeNetworkEnforcementReasonCode(metadata.ReasonCode)
	warnings := sanitizeRuntimeNetworkEnforcementWarningCodeList(metadata.WarningCodes)
	if outcome == "success" && runtimeNetworkEnforcementResultHasDowngradeSignal(reason, warnings) {
		mode = "none"
	}
	capability := SanitizeRuntimeNetworkEnforcementCapability(metadata.Capability)
	if outcome != "success" ||
		!runtimeNetworkEnforcementModeCanEnforce(mode) ||
		runtimeNetworkEnforcementResultHasDowngradeSignal(reason, warnings) {
		capability = nil
	}

	sanitized := &RuntimeNetworkEnforcementResultMetadata{
		PlanID:           sanitizeRuntimeNetworkEnforcementID(metadata.PlanID),
		AdapterID:        sanitizeRuntimeNetworkEnforcementID(metadata.AdapterID),
		Outcome:          outcome,
		EnforcementMode:  mode,
		Mechanisms:       sanitizeRuntimeNetworkEnforcementMechanismList(metadata.Mechanisms),
		Operations:       sanitizeRuntimeNetworkEnforcementIDList(metadata.Operations),
		PolicySnapshotID: sanitizeRuntimeNetworkEnforcementID(metadata.PolicySnapshotID),
		PolicyPreset:     sanitizeRuntimeNetworkEnforcementPolicyPreset(metadata.PolicyPreset),
		Capability:       capability,
		ReasonCode:       reason,
		WarningCodes:     warnings,
	}
	if outcome == "failure" || outcome == "unsupported" {
		sanitized.Capability = nil
	}
	if sanitized.PlanID == "" &&
		sanitized.AdapterID == "" &&
		sanitized.Outcome == "" &&
		sanitized.EnforcementMode == "" &&
		len(sanitized.Mechanisms) == 0 &&
		len(sanitized.Operations) == 0 &&
		sanitized.PolicySnapshotID == "" &&
		sanitized.PolicyPreset == "" &&
		sanitized.Capability == nil &&
		sanitized.ReasonCode == "" &&
		len(sanitized.WarningCodes) == 0 {
		return nil
	}
	return sanitized
}

func runtimeNetworkEnforcementResultHasDowngradeSignal(reason string, warnings []string) bool {
	switch reason {
	case "best_effort", "adapter_unsupported", "adapter_failed", "capability_missing", "mode_unavailable":
		return true
	}
	for _, warning := range warnings {
		switch warning {
		case "partial_enforcement", "unsupported_mode", "capability_downgraded", "metadata_only_fallback", "sanitized_adapter_error":
			return true
		}
	}
	return false
}

func runtimeNetworkEnforcementModeCanEnforce(mode string) bool {
	switch mode {
	case "proxy", "firewall", "runtime", "proxy_firewall":
		return true
	default:
		return false
	}
}

func sanitizeRuntimeNetworkEnforcementSource(value string) string {
	switch normalizeRuntimeNetworkEnforcementEnum(value) {
	case "runtime", "worker", "microvm":
		return normalizeRuntimeNetworkEnforcementEnum(value)
	default:
		return ""
	}
}

func sanitizeRuntimeNetworkEnforcementPolicyPreset(value string) string {
	switch normalizeRuntimeNetworkEnforcementEnum(value) {
	case "deny_by_default", "allow_listed", "legacy_default", "disabled", "no_policy":
		return normalizeRuntimeNetworkEnforcementEnum(value)
	default:
		return ""
	}
}

func sanitizeRuntimeNetworkEnforcementDefaultPosture(value string) string {
	switch normalizeRuntimeNetworkEnforcementEnum(value) {
	case "deny_by_default", "allow_by_default", "no_policy":
		return normalizeRuntimeNetworkEnforcementEnum(value)
	default:
		return ""
	}
}

func sanitizeRuntimeNetworkEnforcementMechanism(value string) string {
	switch normalizeRuntimeNetworkEnforcementEnum(value) {
	case "none", "proxy", "firewall", "runtime":
		return normalizeRuntimeNetworkEnforcementEnum(value)
	default:
		return ""
	}
}

func sanitizeRuntimeNetworkEnforcementMode(value string) string {
	switch normalizeRuntimeNetworkEnforcementEnum(value) {
	case "none", "best_effort", "proxy", "firewall", "runtime", "proxy_firewall":
		return normalizeRuntimeNetworkEnforcementEnum(value)
	default:
		return ""
	}
}

func sanitizeRuntimeNetworkEnforcementOutcome(value string) string {
	switch normalizeRuntimeNetworkEnforcementEnum(value) {
	case "success", "best_effort", "unsupported", "failure":
		return normalizeRuntimeNetworkEnforcementEnum(value)
	default:
		return ""
	}
}

func sanitizeRuntimeNetworkEnforcementReasonCode(value string) string {
	switch normalizeRuntimeNetworkEnforcementEnum(value) {
	case "applied", "best_effort", "adapter_unsupported", "adapter_failed", "capability_missing", "mode_unavailable":
		return normalizeRuntimeNetworkEnforcementEnum(value)
	default:
		return ""
	}
}

func sanitizeRuntimeNetworkEnforcementWarningCode(value string) string {
	switch normalizeRuntimeNetworkEnforcementEnum(value) {
	case "partial_enforcement", "unsupported_mode", "capability_downgraded", "metadata_only_fallback", "sanitized_adapter_error":
		return normalizeRuntimeNetworkEnforcementEnum(value)
	default:
		return ""
	}
}

func sanitizeRuntimeNetworkEnforcementIDList(values []string) []string {
	return sanitizeRuntimeNetworkEnforcementStringList(values, sanitizeRuntimeNetworkEnforcementID)
}

func sanitizeRuntimeNetworkEnforcementMechanismList(values []string) []string {
	return sanitizeRuntimeNetworkEnforcementStringList(values, sanitizeRuntimeNetworkEnforcementMechanism)
}

func sanitizeRuntimeNetworkEnforcementModeList(values []string) []string {
	return sanitizeRuntimeNetworkEnforcementStringList(values, sanitizeRuntimeNetworkEnforcementMode)
}

func sanitizeRuntimeNetworkEnforcementWarningCodeList(values []string) []string {
	return sanitizeRuntimeNetworkEnforcementStringList(values, sanitizeRuntimeNetworkEnforcementWarningCode)
}

func sanitizeRuntimeNetworkEnforcementStringList(values []string, sanitize func(string) string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		safe := sanitize(value)
		if safe == "" || seen[safe] {
			continue
		}
		seen[safe] = true
		out = append(out, safe)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeRuntimeNetworkEnforcementEnum(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func sanitizeRuntimeNetworkEnforcementID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 || runtimeNetworkEnforcementUnsafeFreeform(value) {
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

func runtimeNetworkEnforcementUnsafeFreeform(value string) bool {
	lower := strings.ToLower(value)
	if strings.Contains(lower, "://") ||
		strings.Contains(lower, "/") ||
		strings.Contains(lower, "\\") ||
		strings.Contains(lower, "?") ||
		strings.Contains(lower, "=") ||
		strings.Contains(lower, "@") {
		return true
	}
	for _, marker := range []string{
		"token",
		"secret",
		"password",
		"authorization",
		"bearer",
		"api_key",
		"apikey",
		"credential",
		"hostname",
		"socket",
		"address",
		"port",
		"path",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
