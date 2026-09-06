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
		Plan:          sanitizeRuntimeNetworkEnforcementPlanMetadata(metadata.Plan),
		Orchestration: sanitizeRuntimeNetworkEnforcementOrchestrationMetadata(metadata.Orchestration),
		Result:        sanitizeRuntimeNetworkEnforcementResultMetadata(metadata.Result),
	}
	if sanitized.Plan == nil && sanitized.Orchestration == nil && sanitized.Result == nil {
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

func (metadata RuntimeNetworkEnforcementOrchestrationMetadata) MarshalJSON() ([]byte, error) {
	type runtimeNetworkEnforcementOrchestrationMetadataJSON RuntimeNetworkEnforcementOrchestrationMetadata
	sanitized := sanitizeRuntimeNetworkEnforcementOrchestrationMetadata(&metadata)
	if sanitized == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(runtimeNetworkEnforcementOrchestrationMetadataJSON(*sanitized))
}

func (metadata RuntimeNetworkEnforcementLifecycleMetadata) MarshalJSON() ([]byte, error) {
	type runtimeNetworkEnforcementLifecycleMetadataJSON RuntimeNetworkEnforcementLifecycleMetadata
	sanitized := sanitizeRuntimeNetworkEnforcementLifecycleMetadata(&metadata)
	if sanitized == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(runtimeNetworkEnforcementLifecycleMetadataJSON(*sanitized))
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

func sanitizeRuntimeNetworkEnforcementOrchestrationMetadata(metadata *RuntimeNetworkEnforcementOrchestrationMetadata) *RuntimeNetworkEnforcementOrchestrationMetadata {
	if metadata == nil {
		return nil
	}
	sanitized := &RuntimeNetworkEnforcementOrchestrationMetadata{
		PlanID:           sanitizeRuntimeNetworkEnforcementID(metadata.PlanID),
		AdapterID:        sanitizeRuntimeNetworkEnforcementID(metadata.AdapterID),
		Status:           sanitizeRuntimeNetworkEnforcementLifecycleStatus(metadata.Status),
		Mechanisms:       sanitizeRuntimeNetworkEnforcementMechanismList(metadata.Mechanisms),
		Operations:       sanitizeRuntimeNetworkEnforcementIDList(metadata.Operations),
		PolicySnapshotID: sanitizeRuntimeNetworkEnforcementID(metadata.PolicySnapshotID),
		PolicyPreset:     sanitizeRuntimeNetworkEnforcementPolicyPreset(metadata.PolicyPreset),
		Proxy:            sanitizeRuntimeNetworkEnforcementLifecycleMetadata(metadata.Proxy),
		Rules:            sanitizeRuntimeNetworkEnforcementLifecycleMetadataList(metadata.Rules),
		CapabilityLabels: sanitizeRuntimeNetworkEnforcementIDList(metadata.CapabilityLabels),
		ReasonCode:       sanitizeRuntimeNetworkEnforcementLifecycleReasonCode(metadata.ReasonCode),
		WarningCodes:     sanitizeRuntimeNetworkEnforcementLifecycleWarningCodeList(metadata.WarningCodes),
	}
	if sanitized.PlanID == "" &&
		sanitized.AdapterID == "" &&
		sanitized.Status == "" &&
		len(sanitized.Mechanisms) == 0 &&
		len(sanitized.Operations) == 0 &&
		sanitized.PolicySnapshotID == "" &&
		sanitized.PolicyPreset == "" &&
		sanitized.Proxy == nil &&
		len(sanitized.Rules) == 0 &&
		len(sanitized.CapabilityLabels) == 0 &&
		sanitized.ReasonCode == "" &&
		len(sanitized.WarningCodes) == 0 {
		return nil
	}
	return sanitized
}

func sanitizeRuntimeNetworkEnforcementLifecycleMetadata(metadata *RuntimeNetworkEnforcementLifecycleMetadata) *RuntimeNetworkEnforcementLifecycleMetadata {
	if metadata == nil {
		return nil
	}
	sanitized := &RuntimeNetworkEnforcementLifecycleMetadata{
		ID:               sanitizeRuntimeNetworkEnforcementID(metadata.ID),
		PlanID:           sanitizeRuntimeNetworkEnforcementID(metadata.PlanID),
		AdapterID:        sanitizeRuntimeNetworkEnforcementID(metadata.AdapterID),
		Status:           sanitizeRuntimeNetworkEnforcementLifecycleStatus(metadata.Status),
		Mechanisms:       sanitizeRuntimeNetworkEnforcementMechanismList(metadata.Mechanisms),
		Operations:       sanitizeRuntimeNetworkEnforcementIDList(metadata.Operations),
		PolicySnapshotID: sanitizeRuntimeNetworkEnforcementID(metadata.PolicySnapshotID),
		PolicyPreset:     sanitizeRuntimeNetworkEnforcementPolicyPreset(metadata.PolicyPreset),
		CapabilityLabels: sanitizeRuntimeNetworkEnforcementIDList(metadata.CapabilityLabels),
		ReasonCode:       sanitizeRuntimeNetworkEnforcementLifecycleReasonCode(metadata.ReasonCode),
		WarningCodes:     sanitizeRuntimeNetworkEnforcementLifecycleWarningCodeList(metadata.WarningCodes),
	}
	if sanitized.ID == "" &&
		sanitized.PlanID == "" &&
		sanitized.AdapterID == "" &&
		sanitized.Status == "" &&
		len(sanitized.Mechanisms) == 0 &&
		len(sanitized.Operations) == 0 &&
		sanitized.PolicySnapshotID == "" &&
		sanitized.PolicyPreset == "" &&
		len(sanitized.CapabilityLabels) == 0 &&
		sanitized.ReasonCode == "" &&
		len(sanitized.WarningCodes) == 0 {
		return nil
	}
	return sanitized
}

func sanitizeRuntimeNetworkEnforcementLifecycleMetadataList(values []RuntimeNetworkEnforcementLifecycleMetadata) []RuntimeNetworkEnforcementLifecycleMetadata {
	if len(values) == 0 {
		return nil
	}
	out := make([]RuntimeNetworkEnforcementLifecycleMetadata, 0, len(values))
	for _, value := range values {
		sanitized := sanitizeRuntimeNetworkEnforcementLifecycleMetadata(&value)
		if sanitized != nil {
			out = append(out, *sanitized)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sanitizeRuntimeNetworkEnforcementResultMetadata(metadata *RuntimeNetworkEnforcementResultMetadata) *RuntimeNetworkEnforcementResultMetadata {
	if metadata == nil {
		return nil
	}
	outcome := sanitizeRuntimeNetworkEnforcementOutcome(metadata.Outcome)
	mode := sanitizeRuntimeNetworkEnforcementMode(metadata.EnforcementMode)
	mechanisms := sanitizeRuntimeNetworkEnforcementMechanismList(metadata.Mechanisms)
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
	mode = runtimeNetworkEnforcementModeConsistentWithMechanisms(mode, mechanisms)
	reason := sanitizeRuntimeNetworkEnforcementReasonCode(metadata.ReasonCode)
	warnings := sanitizeRuntimeNetworkEnforcementWarningCodeList(metadata.WarningCodes)
	if outcome == "success" && runtimeNetworkEnforcementResultHasDowngradeSignal(reason, warnings) {
		mode = "none"
	}
	capability := SanitizeRuntimeNetworkEnforcementCapability(metadata.Capability)
	capability = runtimeNetworkEnforcementCapabilityConsistentWithMode(capability, mode)
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
		Mechanisms:       mechanisms,
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

func runtimeNetworkEnforcementModeConsistentWithMechanisms(mode string, mechanisms []string) string {
	if mode != "proxy_firewall" {
		return mode
	}
	hasProxy := runtimeNetworkEnforcementStringListContains(mechanisms, "proxy")
	hasFirewall := runtimeNetworkEnforcementStringListContains(mechanisms, "firewall")
	hasRuntime := runtimeNetworkEnforcementStringListContains(mechanisms, "runtime")
	switch {
	case hasProxy && hasFirewall:
		return mode
	case hasRuntime:
		return "runtime"
	case hasProxy:
		return "proxy"
	case hasFirewall:
		return "firewall"
	default:
		return "none"
	}
}

func runtimeNetworkEnforcementCapabilityConsistentWithMode(capability *RuntimeNetworkEnforcementCapability, mode string) *RuntimeNetworkEnforcementCapability {
	if capability == nil {
		return nil
	}
	copied := *capability
	copied.Modes = runtimeNetworkEnforcementCapabilityModesForMode(capability.Modes, mode, capability.Supported)
	if mode == "proxy" || mode == "best_effort" || mode == "none" {
		copied.SupportsDefaultDenyPosture = false
	}
	return SanitizeRuntimeNetworkEnforcementCapability(&copied)
}

func runtimeNetworkEnforcementCapabilityModesForMode(values []string, mode string, supported bool) []string {
	if mode == "" || mode == "none" || mode == "best_effort" {
		return nil
	}
	var out []string
	for _, value := range values {
		if sanitizeRuntimeNetworkEnforcementMode(value) == mode && !runtimeNetworkEnforcementStringListContains(out, mode) {
			out = append(out, mode)
		}
	}
	if len(out) == 0 && supported && runtimeNetworkEnforcementModeCanEnforce(mode) {
		out = append(out, mode)
	}
	return out
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

func runtimeNetworkEnforcementStringListContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
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

func sanitizeRuntimeNetworkEnforcementLifecycleStatus(value string) string {
	switch normalizeRuntimeNetworkEnforcementEnum(value) {
	case "requested", "planned", "prepared", "starting", "applying", "active", "rolling_back", "cleaning_up", "stopped", "failed", "skipped":
		return normalizeRuntimeNetworkEnforcementEnum(value)
	default:
		return ""
	}
}

func sanitizeRuntimeNetworkEnforcementLifecycleReasonCode(value string) string {
	switch normalizeRuntimeNetworkEnforcementEnum(value) {
	case "prepared", "started", "applied", "active", "stopped", "skipped", "adapter_unsupported", "adapter_failed", "capability_missing", "cleanup_failed", "rollback_failed", "active_check_failed":
		return normalizeRuntimeNetworkEnforcementEnum(value)
	default:
		return ""
	}
}

func sanitizeRuntimeNetworkEnforcementLifecycleWarningCode(value string) string {
	switch normalizeRuntimeNetworkEnforcementEnum(value) {
	case "cleanup_failed", "rollback_failed", "active_check_failed", "partial_lifecycle", "unsupported_mechanism", "sanitized_adapter_error", "metadata_only_fallback":
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

func sanitizeRuntimeNetworkEnforcementLifecycleWarningCodeList(values []string) []string {
	return sanitizeRuntimeNetworkEnforcementStringList(values, sanitizeRuntimeNetworkEnforcementLifecycleWarningCode)
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
