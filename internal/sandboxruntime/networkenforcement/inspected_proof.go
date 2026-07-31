package networkenforcement

import "encoding/json"

// EnforcementCorrelation binds every live component that contributes to one
// network-enforcement claim. It contains only safe opaque identifiers.
type EnforcementCorrelation struct {
	SandboxID            string `json:"sandboxId,omitempty"`
	ExecutionID          string `json:"executionId,omitempty"`
	WorkerID             string `json:"workerId,omitempty"`
	RuntimeID            string `json:"runtimeId,omitempty"`
	PlanID               string `json:"planId,omitempty"`
	PolicySnapshotID     string `json:"policySnapshotId,omitempty"`
	ProxySessionID       string `json:"proxySessionId,omitempty"`
	TopologyGenerationID string `json:"topologyGenerationId,omitempty"`
	RuleGenerationID     string `json:"ruleGenerationId,omitempty"`
}

// RuleInspectionStatus distinguishes apply acknowledgement from structural
// inspection of the exact live rule generation.
type RuleInspectionStatus string

const (
	RuleInspectionStatusApplied   RuleInspectionStatus = "applied"
	RuleInspectionStatusInspected RuleInspectionStatus = "inspected"
	RuleInspectionStatusAbsent    RuleInspectionStatus = "absent"
	RuleInspectionStatusStale     RuleInspectionStatus = "stale"
)

// InspectedRuleProof is safe public evidence derived from a bounded structural
// inspection. It intentionally carries no namespace, interface, address,
// port, table, chain, rule body, handle, process, or command data.
type InspectedRuleProof struct {
	ID               string                  `json:"id,omitempty"`
	RuleDigest       string                  `json:"ruleDigest,omitempty"`
	Status           RuleInspectionStatus    `json:"status,omitempty"`
	Correlation      *EnforcementCorrelation `json:"correlation,omitempty"`
	Mechanisms       []EnforcementMechanism  `json:"mechanisms,omitempty"`
	CapabilityLabels []string                `json:"capabilityLabels,omitempty"`
	ReasonCode       LifecycleReasonCode     `json:"reasonCode,omitempty"`
	WarningCodes     []LifecycleWarningCode  `json:"warningCodes,omitempty"`
}

// SanitizeEnforcementCorrelation returns a copy containing safe identifiers
// only. Completeness is checked separately so partial data remains visibly
// non-authoritative.
func SanitizeEnforcementCorrelation(value EnforcementCorrelation) EnforcementCorrelation {
	return EnforcementCorrelation{
		SandboxID:            sanitizeIdentifier(value.SandboxID),
		ExecutionID:          sanitizeIdentifier(value.ExecutionID),
		WorkerID:             sanitizeIdentifier(value.WorkerID),
		RuntimeID:            sanitizeIdentifier(value.RuntimeID),
		PlanID:               sanitizeIdentifier(value.PlanID),
		PolicySnapshotID:     sanitizeIdentifier(value.PolicySnapshotID),
		ProxySessionID:       sanitizeIdentifier(value.ProxySessionID),
		TopologyGenerationID: sanitizeIdentifier(value.TopologyGenerationID),
		RuleGenerationID:     sanitizeIdentifier(value.RuleGenerationID),
	}
}

// EnforcementCorrelationComplete reports whether every required safe identity
// is present. Unsafe values sanitize to empty and therefore fail closed.
func EnforcementCorrelationComplete(value EnforcementCorrelation) bool {
	sanitized := SanitizeEnforcementCorrelation(value)
	return sanitized.SandboxID != "" &&
		sanitized.ExecutionID != "" &&
		sanitized.WorkerID != "" &&
		sanitized.RuntimeID != "" &&
		sanitized.PlanID != "" &&
		sanitized.PolicySnapshotID != "" &&
		sanitized.ProxySessionID != "" &&
		sanitized.TopologyGenerationID != "" &&
		sanitized.RuleGenerationID != ""
}

// EnforcementCorrelationsEqual requires complete, field-for-field identity.
func EnforcementCorrelationsEqual(left, right EnforcementCorrelation) bool {
	left = SanitizeEnforcementCorrelation(left)
	right = SanitizeEnforcementCorrelation(right)
	return EnforcementCorrelationComplete(left) &&
		EnforcementCorrelationComplete(right) &&
		left == right
}

// SanitizeInspectedRuleProof returns safe proof metadata. An inspected claim
// with incomplete or unsafe identity is downgraded to stale proof.
func SanitizeInspectedRuleProof(value InspectedRuleProof) InspectedRuleProof {
	correlation := sanitizeEnforcementCorrelationPtr(value.Correlation)
	sanitized := InspectedRuleProof{
		ID:               sanitizeIdentifier(value.ID),
		RuleDigest:       sanitizeIdentifier(value.RuleDigest),
		Status:           sanitizeRuleInspectionStatus(value.Status),
		Correlation:      correlation,
		Mechanisms:       sanitizeEnforcementMechanismList(value.Mechanisms),
		CapabilityLabels: sanitizeIdentifierList(value.CapabilityLabels),
		ReasonCode:       sanitizeLifecycleReasonCode(value.ReasonCode),
		WarningCodes:     sanitizeLifecycleWarningCodeList(value.WarningCodes),
	}
	inputInvalid := (value.ID != "" && sanitized.ID == "") ||
		(value.RuleDigest != "" && sanitized.RuleDigest == "") ||
		(value.Correlation != nil && correlation == nil) ||
		len(value.Mechanisms) != len(sanitized.Mechanisms) ||
		len(value.CapabilityLabels) != len(sanitized.CapabilityLabels) ||
		len(value.WarningCodes) != len(sanitized.WarningCodes)
	if sanitized.Status == RuleInspectionStatusInspected &&
		(inputInvalid || sanitized.ID == "" ||
			sanitized.RuleDigest == "" ||
			sanitized.Correlation == nil ||
			!EnforcementCorrelationComplete(*sanitized.Correlation) ||
			len(sanitized.Mechanisms) == 0 ||
			len(sanitized.CapabilityLabels) == 0 ||
			len(sanitized.WarningCodes) > 0) {
		sanitized.Status = RuleInspectionStatusStale
		sanitized.ReasonCode = LifecycleReasonProofMismatch
		sanitized.WarningCodes = appendLifecycleWarnings(sanitized.WarningCodes, LifecycleWarningProofMismatch)
	}
	return sanitized
}

func (value EnforcementCorrelation) MarshalJSON() ([]byte, error) {
	type correlationJSON EnforcementCorrelation
	return json.Marshal(correlationJSON(SanitizeEnforcementCorrelation(value)))
}

func (value InspectedRuleProof) MarshalJSON() ([]byte, error) {
	type proofJSON InspectedRuleProof
	return json.Marshal(proofJSON(SanitizeInspectedRuleProof(value)))
}

func sanitizeEnforcementCorrelationPtr(value *EnforcementCorrelation) *EnforcementCorrelation {
	if value == nil {
		return nil
	}
	sanitized := SanitizeEnforcementCorrelation(*value)
	if sanitized == (EnforcementCorrelation{}) {
		return nil
	}
	return &sanitized
}

func sanitizeInspectedRuleProofPtr(value *InspectedRuleProof) *InspectedRuleProof {
	if value == nil {
		return nil
	}
	sanitized := SanitizeInspectedRuleProof(*value)
	if inspectedRuleProofEmpty(sanitized) {
		return nil
	}
	return &sanitized
}

func inspectedRuleProofEmpty(value InspectedRuleProof) bool {
	return value.ID == "" && value.RuleDigest == "" && value.Status == "" &&
		value.Correlation == nil && len(value.Mechanisms) == 0 &&
		len(value.CapabilityLabels) == 0 && value.ReasonCode == "" &&
		len(value.WarningCodes) == 0
}

func sanitizeRuleInspectionStatus(value RuleInspectionStatus) RuleInspectionStatus {
	normalized := RuleInspectionStatus(normalizeEnum(string(value)))
	switch normalized {
	case RuleInspectionStatusApplied,
		RuleInspectionStatusInspected,
		RuleInspectionStatusAbsent,
		RuleInspectionStatusStale:
		return normalized
	default:
		return ""
	}
}
