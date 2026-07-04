package livegate

import (
	"encoding/json"
	"strings"
)

// GateID identifies a live gate without carrying paths, endpoints, or
// credential-bearing runtime configuration.
type GateID string

// GateCategory groups live gates by optional verification domain.
type GateCategory string

const (
	GateCategoryFirecracker        GateCategory = "firecracker"
	GateCategoryNetworkEnforcement GateCategory = "network_enforcement"
	GateCategoryCredentialDelivery GateCategory = "credential_delivery"
	GateCategoryWorkerIntegration  GateCategory = "worker_integration"
	GateCategoryPodmanIntegration  GateCategory = "podman_integration"
)

// BuildTagName is the safe name of an optional Go build tag required by a
// live gate.
type BuildTagName string

const (
	BuildTagFirecrackerLive        BuildTagName = "firecracker_live"
	BuildTagNetworkEnforcementLive BuildTagName = "network_enforcement_live"
	BuildTagCredentialDeliveryLive BuildTagName = "credential_delivery_live"
	BuildTagWorkerIntegrationLive  BuildTagName = "worker_integration"
	BuildTagPodmanIntegrationLive  BuildTagName = "podman_integration"
)

// EnvVarName is the safe name of an environment marker. It never includes the
// marker value.
type EnvVarName string

const (
	EnvVarFirecrackerLive        EnvVarName = "HAL_FIRECRACKER_LIVE"
	EnvVarNetworkEnforcementLive EnvVarName = "HAL_NETWORK_ENFORCEMENT_LIVE"
	EnvVarCredentialDeliveryLive EnvVarName = "HAL_CREDENTIAL_DELIVERY_LIVE"
	EnvVarWorkerIntegrationLive  EnvVarName = "HAL_WORKER_INTEGRATION_LIVE"
	EnvVarPodmanIntegrationLive  EnvVarName = "HAL_PODMAN_INTEGRATION_LIVE"
)

// CapabilityID identifies a declared live capability without importing the
// implementation that may prove or exercise it.
type CapabilityID string

const (
	CapabilityFirecrackerMicroVM CapabilityID = "firecracker_microvm"
	CapabilityNetworkEnforcement CapabilityID = "network_enforcement"
	CapabilityCredentialDelivery CapabilityID = "credential_delivery"
	CapabilityWorkerIntegration  CapabilityID = "worker_integration"
	CapabilityPodmanIntegration  CapabilityID = "podman_integration"
)

// RequirementStatus is the redaction-safe state of a gate prerequisite.
type RequirementStatus string

const (
	RequirementStatusSatisfied   RequirementStatus = "satisfied"
	RequirementStatusMissing     RequirementStatus = "missing"
	RequirementStatusUnavailable RequirementStatus = "unavailable"
	RequirementStatusSkipped     RequirementStatus = "skipped"
)

// SkipReasonCode explains why a live gate did not allow a live action.
type SkipReasonCode string

const (
	SkipReasonMissingBuildTag       SkipReasonCode = "missing_build_tag"
	SkipReasonMissingEnvVar         SkipReasonCode = "missing_env_var"
	SkipReasonCapabilityUnavailable SkipReasonCode = "capability_unavailable"
	SkipReasonGateDisabled          SkipReasonCode = "gate_disabled"
	SkipReasonUnsupportedPlatform   SkipReasonCode = "unsupported_platform"
)

// RemediationCommandLabel names a safe remediation action without embedding a
// command line, local path, environment value, endpoint, or provider config.
type RemediationCommandLabel string

const (
	RemediationEnableBuildTag    RemediationCommandLabel = "enable_build_tag"
	RemediationSetEnvVar         RemediationCommandLabel = "set_env_var"
	RemediationInstallCapability RemediationCommandLabel = "install_capability"
)

// Gate is the public live gate contract shared by future evaluators and test
// helpers. It carries only safe identifiers, enum-like values, and remediation
// labels.
type Gate struct {
	ID           GateID               `json:"gateId,omitempty"`
	Category     GateCategory         `json:"category,omitempty"`
	BuildTags    []BuildTagName       `json:"buildTags,omitempty"`
	EnvVars      []EnvVarName         `json:"envVars,omitempty"`
	Capabilities []CapabilityID       `json:"capabilities,omitempty"`
	Requirements []Requirement        `json:"requirements,omitempty"`
	Remediation  *RemediationMetadata `json:"remediation,omitempty"`
}

// Requirement records one build-tag, environment-marker, or capability
// prerequisite using safe metadata only.
type Requirement struct {
	Status      RequirementStatus    `json:"status,omitempty"`
	BuildTag    BuildTagName         `json:"buildTag,omitempty"`
	EnvVar      EnvVarName           `json:"envVar,omitempty"`
	Capability  CapabilityID         `json:"capability,omitempty"`
	ReasonCode  SkipReasonCode       `json:"reasonCode,omitempty"`
	Remediation *RemediationMetadata `json:"remediation,omitempty"`
}

// CapabilityRequirement records capability-specific gate status without
// importing provider, runtime, worker, or command code.
type CapabilityRequirement struct {
	ID          CapabilityID         `json:"capabilityId,omitempty"`
	Status      RequirementStatus    `json:"status,omitempty"`
	ReasonCode  SkipReasonCode       `json:"reasonCode,omitempty"`
	Remediation *RemediationMetadata `json:"remediation,omitempty"`
}

// RemediationMetadata exposes safe hints a caller can render when a live gate
// skips. CommandLabels are labels only, not shell commands.
type RemediationMetadata struct {
	ReasonCode    SkipReasonCode            `json:"reasonCode,omitempty"`
	BuildTags     []BuildTagName            `json:"buildTags,omitempty"`
	EnvVars       []EnvVarName              `json:"envVars,omitempty"`
	Capabilities  []CapabilityID            `json:"capabilities,omitempty"`
	CommandLabels []RemediationCommandLabel `json:"commandLabels,omitempty"`
}

func (g Gate) MarshalJSON() ([]byte, error) {
	type gateJSON Gate
	sanitized := SanitizeGate(g)
	return json.Marshal(gateJSON(sanitized))
}

func (r Requirement) MarshalJSON() ([]byte, error) {
	type requirementJSON Requirement
	sanitized := SanitizeRequirement(r)
	return json.Marshal(requirementJSON(sanitized))
}

func (r CapabilityRequirement) MarshalJSON() ([]byte, error) {
	type capabilityRequirementJSON CapabilityRequirement
	sanitized := SanitizeCapabilityRequirement(r)
	return json.Marshal(capabilityRequirementJSON(sanitized))
}

func (r RemediationMetadata) MarshalJSON() ([]byte, error) {
	type remediationMetadataJSON RemediationMetadata
	sanitized := SanitizeRemediationMetadata(r)
	return json.Marshal(remediationMetadataJSON(sanitized))
}

// SanitizeGate returns a redaction-safe copy that is suitable for durable JSON.
func SanitizeGate(g Gate) Gate {
	return Gate{
		ID:           sanitizeGateID(g.ID),
		Category:     sanitizeGateCategory(g.Category),
		BuildTags:    sanitizeBuildTagList(g.BuildTags),
		EnvVars:      sanitizeEnvVarList(g.EnvVars),
		Capabilities: sanitizeCapabilityIDList(g.Capabilities),
		Requirements: sanitizeRequirementList(g.Requirements),
		Remediation:  sanitizeRemediationMetadataPtr(g.Remediation),
	}
}

// SanitizeRequirement returns a redaction-safe requirement copy.
func SanitizeRequirement(r Requirement) Requirement {
	return Requirement{
		Status:      sanitizeRequirementStatus(r.Status),
		BuildTag:    sanitizeBuildTagName(r.BuildTag),
		EnvVar:      sanitizeEnvVarName(r.EnvVar),
		Capability:  sanitizeCapabilityID(r.Capability),
		ReasonCode:  sanitizeSkipReasonCode(r.ReasonCode),
		Remediation: sanitizeRemediationMetadataPtr(r.Remediation),
	}
}

// SanitizeCapabilityRequirement returns a redaction-safe capability requirement
// copy.
func SanitizeCapabilityRequirement(r CapabilityRequirement) CapabilityRequirement {
	return CapabilityRequirement{
		ID:          sanitizeCapabilityID(r.ID),
		Status:      sanitizeRequirementStatus(r.Status),
		ReasonCode:  sanitizeSkipReasonCode(r.ReasonCode),
		Remediation: sanitizeRemediationMetadataPtr(r.Remediation),
	}
}

// SanitizeRemediationMetadata returns a redaction-safe remediation copy.
func SanitizeRemediationMetadata(r RemediationMetadata) RemediationMetadata {
	return RemediationMetadata{
		ReasonCode:    sanitizeSkipReasonCode(r.ReasonCode),
		BuildTags:     sanitizeBuildTagList(r.BuildTags),
		EnvVars:       sanitizeEnvVarList(r.EnvVars),
		Capabilities:  sanitizeCapabilityIDList(r.Capabilities),
		CommandLabels: sanitizeRemediationCommandLabelList(r.CommandLabels),
	}
}

func sanitizeGateID(value GateID) GateID {
	return GateID(sanitizeSafeLabel(string(value)))
}

func sanitizeGateCategory(value GateCategory) GateCategory {
	normalized := GateCategory(normalizeEnum(string(value)))
	switch normalized {
	case GateCategoryFirecracker,
		GateCategoryNetworkEnforcement,
		GateCategoryCredentialDelivery,
		GateCategoryWorkerIntegration,
		GateCategoryPodmanIntegration:
		return normalized
	default:
		return ""
	}
}

func sanitizeBuildTagName(value BuildTagName) BuildTagName {
	normalized := strings.ToLower(strings.TrimSpace(string(value)))
	if !safeBuildTagName(normalized) {
		return ""
	}
	return BuildTagName(normalized)
}

func sanitizeEnvVarName(value EnvVarName) EnvVarName {
	normalized := strings.TrimSpace(string(value))
	if !safeEnvVarName(normalized) {
		return ""
	}
	return EnvVarName(normalized)
}

func sanitizeCapabilityID(value CapabilityID) CapabilityID {
	return CapabilityID(sanitizeSafeLabel(string(value)))
}

func sanitizeRequirementStatus(value RequirementStatus) RequirementStatus {
	normalized := RequirementStatus(normalizeEnum(string(value)))
	switch normalized {
	case RequirementStatusSatisfied,
		RequirementStatusMissing,
		RequirementStatusUnavailable,
		RequirementStatusSkipped:
		return normalized
	default:
		return ""
	}
}

func sanitizeSkipReasonCode(value SkipReasonCode) SkipReasonCode {
	normalized := SkipReasonCode(normalizeEnum(string(value)))
	switch normalized {
	case SkipReasonMissingBuildTag,
		SkipReasonMissingEnvVar,
		SkipReasonCapabilityUnavailable,
		SkipReasonGateDisabled,
		SkipReasonUnsupportedPlatform:
		return normalized
	default:
		return ""
	}
}

func sanitizeRemediationCommandLabel(value RemediationCommandLabel) RemediationCommandLabel {
	return RemediationCommandLabel(sanitizeSafeLabel(string(value)))
}

func sanitizeBuildTagList(values []BuildTagName) []BuildTagName {
	if len(values) == 0 {
		return nil
	}
	out := make([]BuildTagName, 0, len(values))
	for _, value := range values {
		sanitized := sanitizeBuildTagName(value)
		if sanitized != "" {
			out = append(out, sanitized)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sanitizeEnvVarList(values []EnvVarName) []EnvVarName {
	if len(values) == 0 {
		return nil
	}
	out := make([]EnvVarName, 0, len(values))
	for _, value := range values {
		sanitized := sanitizeEnvVarName(value)
		if sanitized != "" {
			out = append(out, sanitized)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sanitizeCapabilityIDList(values []CapabilityID) []CapabilityID {
	if len(values) == 0 {
		return nil
	}
	out := make([]CapabilityID, 0, len(values))
	for _, value := range values {
		sanitized := sanitizeCapabilityID(value)
		if sanitized != "" {
			out = append(out, sanitized)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sanitizeRemediationCommandLabelList(values []RemediationCommandLabel) []RemediationCommandLabel {
	if len(values) == 0 {
		return nil
	}
	out := make([]RemediationCommandLabel, 0, len(values))
	for _, value := range values {
		sanitized := sanitizeRemediationCommandLabel(value)
		if sanitized != "" {
			out = append(out, sanitized)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sanitizeRequirementList(values []Requirement) []Requirement {
	if len(values) == 0 {
		return nil
	}
	out := make([]Requirement, 0, len(values))
	for _, value := range values {
		sanitized := SanitizeRequirement(value)
		if !requirementEmpty(sanitized) {
			out = append(out, sanitized)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sanitizeRemediationMetadataPtr(value *RemediationMetadata) *RemediationMetadata {
	if value == nil {
		return nil
	}
	sanitized := SanitizeRemediationMetadata(*value)
	if remediationMetadataEmpty(sanitized) {
		return nil
	}
	return &sanitized
}

func requirementEmpty(r Requirement) bool {
	return r.Status == "" &&
		r.BuildTag == "" &&
		r.EnvVar == "" &&
		r.Capability == "" &&
		r.ReasonCode == "" &&
		r.Remediation == nil
}

func remediationMetadataEmpty(r RemediationMetadata) bool {
	return r.ReasonCode == "" &&
		len(r.BuildTags) == 0 &&
		len(r.EnvVars) == 0 &&
		len(r.Capabilities) == 0 &&
		len(r.CommandLabels) == 0
}

func sanitizeSafeLabel(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if !safeLabel(normalized) {
		return ""
	}
	return normalized
}

func normalizeEnum(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "-", "_")
	return strings.ToLower(value)
}

func safeBuildTagName(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' {
			continue
		}
		return false
	}
	return value[0] >= 'a' && value[0] <= 'z'
}

func safeEnvVarName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	first := value[0]
	if !((first >= 'A' && first <= 'Z') || first == '_') {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			continue
		}
		return false
	}
	return true
}

func safeLabel(value string) bool {
	if value == "" || len(value) > 96 {
		return false
	}
	if hasUnsafeFragment(value) {
		return false
	}
	first := value[0]
	if !((first >= 'a' && first <= 'z') || (first >= '0' && first <= '9')) {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-' {
			continue
		}
		return false
	}
	return true
}

func hasUnsafeFragment(value string) bool {
	for _, fragment := range []string{
		"://",
		"/",
		"\\",
		" ",
		"\t",
		"\n",
		"\r",
		"=",
		":",
		"@",
		"$",
		"'",
		"\"",
		"`",
		"{",
		"}",
		"[",
		"]",
		"(",
		")",
		",",
		";",
		"|",
		"&",
		"*",
		"?",
		"#",
		"ghp_",
		"github_pat_",
		"xoxb-",
		"xoxp-",
		"sk-",
		"bearer",
		"authorization",
	} {
		if strings.Contains(value, fragment) {
			return true
		}
	}
	return false
}
