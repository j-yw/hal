package sandbox

// SandboxSecurityCapabilityReadinessGatePolicyMode is the opt-in policy mode
// for readiness gate decisions.
type SandboxSecurityCapabilityReadinessGatePolicyMode string

const (
	SandboxSecurityCapabilityReadinessGatePolicyModeOff      SandboxSecurityCapabilityReadinessGatePolicyMode = "off"
	SandboxSecurityCapabilityReadinessGatePolicyModeAdvisory SandboxSecurityCapabilityReadinessGatePolicyMode = "advisory"
	SandboxSecurityCapabilityReadinessGatePolicyModeStrict   SandboxSecurityCapabilityReadinessGatePolicyMode = "strict"
)

// SandboxSecurityCapabilityReadinessGateOutcome is the stable machine result
// of applying a readiness gate policy.
type SandboxSecurityCapabilityReadinessGateOutcome string

const (
	SandboxSecurityCapabilityReadinessGateOutcomeAllowed  SandboxSecurityCapabilityReadinessGateOutcome = "allowed"
	SandboxSecurityCapabilityReadinessGateOutcomeAdvisory SandboxSecurityCapabilityReadinessGateOutcome = "advisory"
	SandboxSecurityCapabilityReadinessGateOutcomeBlocked  SandboxSecurityCapabilityReadinessGateOutcome = "blocked"
)

// SandboxSecurityCapabilityReadinessGateCode is a redaction-safe decision
// code for readiness gate metadata.
type SandboxSecurityCapabilityReadinessGateCode string

const (
	SandboxSecurityCapabilityReadinessGateCodeAllowed  SandboxSecurityCapabilityReadinessGateCode = "security_readiness_gate_allowed"
	SandboxSecurityCapabilityReadinessGateCodeAdvisory SandboxSecurityCapabilityReadinessGateCode = "security_readiness_gate_advisory"
	SandboxSecurityCapabilityReadinessGateCodeBlocked  SandboxSecurityCapabilityReadinessGateCode = "security_readiness_gate_blocked"
)

// SandboxSecurityCapabilityReadinessGateReasonCode is a redaction-safe
// explanation label for a readiness gate decision.
type SandboxSecurityCapabilityReadinessGateReasonCode string

const (
	SandboxSecurityCapabilityReadinessGateReasonPolicyOff             SandboxSecurityCapabilityReadinessGateReasonCode = "policy_off"
	SandboxSecurityCapabilityReadinessGateReasonPolicyAdvisory        SandboxSecurityCapabilityReadinessGateReasonCode = "policy_advisory"
	SandboxSecurityCapabilityReadinessGateReasonReadinessReady        SandboxSecurityCapabilityReadinessGateReasonCode = "readiness_ready"
	SandboxSecurityCapabilityReadinessGateReasonReadinessMissing      SandboxSecurityCapabilityReadinessGateReasonCode = "readiness_missing"
	SandboxSecurityCapabilityReadinessGateReasonMetadataOnly          SandboxSecurityCapabilityReadinessGateReasonCode = "metadata_only"
	SandboxSecurityCapabilityReadinessGateReasonCapabilityUnsupported SandboxSecurityCapabilityReadinessGateReasonCode = "capability_unsupported"
	SandboxSecurityCapabilityReadinessGateReasonCapabilityBlocked     SandboxSecurityCapabilityReadinessGateReasonCode = "capability_blocked"
	SandboxSecurityCapabilityReadinessGateReasonStrictBlockRequired   SandboxSecurityCapabilityReadinessGateReasonCode = "strict_block_required"
	SandboxSecurityCapabilityReadinessGateReasonUnknown               SandboxSecurityCapabilityReadinessGateReasonCode = "unknown"
)

// SandboxSecurityCapabilityReadinessGateCounts carries aggregate diagnostic
// counts only. It must not include raw policy values or runtime metadata.
type SandboxSecurityCapabilityReadinessGateCounts struct {
	Total          int `json:"total,omitempty"`
	Ready          int `json:"ready,omitempty"`
	Advisory       int `json:"advisory,omitempty"`
	Blocked        int `json:"blocked,omitempty"`
	Missing        int `json:"missing,omitempty"`
	MetadataOnly   int `json:"metadataOnly,omitempty"`
	Unsupported    int `json:"unsupported,omitempty"`
	StrictBlocking int `json:"strictBlocking,omitempty"`
}

// SandboxSecurityCapabilityReadinessGateDecision is the additive,
// redaction-safe readiness gate metadata surface.
type SandboxSecurityCapabilityReadinessGateDecision struct {
	Code       SandboxSecurityCapabilityReadinessGateCode       `json:"code,omitempty"`
	Outcome    SandboxSecurityCapabilityReadinessGateOutcome    `json:"outcome,omitempty"`
	PolicyMode SandboxSecurityCapabilityReadinessGatePolicyMode `json:"policyMode,omitempty"`
	Reason     SandboxSecurityCapabilityReadinessGateReasonCode `json:"reason,omitempty"`
	Counts     *SandboxSecurityCapabilityReadinessGateCounts    `json:"counts,omitempty"`
}

// EvaluateSandboxSecurityCapabilityReadinessGateFromOutput derives advisory
// diagnostics from readiness output before evaluating the gate policy.
func EvaluateSandboxSecurityCapabilityReadinessGateFromOutput(mode SandboxSecurityCapabilityReadinessGatePolicyMode, output SandboxSecurityCapabilityReadinessOutput) SandboxSecurityCapabilityReadinessGateDecision {
	return EvaluateSandboxSecurityCapabilityReadinessGate(mode, DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(output))
}

// EvaluateSandboxSecurityCapabilityReadinessGate converts advisory readiness
// diagnostics into a deterministic, redaction-safe policy decision.
func EvaluateSandboxSecurityCapabilityReadinessGate(mode SandboxSecurityCapabilityReadinessGatePolicyMode, diagnostics SandboxSecurityCapabilityReadinessDiagnosticSummary) SandboxSecurityCapabilityReadinessGateDecision {
	policyMode := normalizeSandboxSecurityCapabilityReadinessGatePolicyMode(mode)
	counts, strictReason := sandboxSecurityCapabilityReadinessGateCounts(diagnostics)

	switch policyMode {
	case SandboxSecurityCapabilityReadinessGatePolicyModeStrict:
		if counts.StrictBlocking > 0 {
			return sandboxSecurityCapabilityReadinessGateDecision(
				SandboxSecurityCapabilityReadinessGateCodeBlocked,
				SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
				policyMode,
				strictReason,
				counts,
			)
		}
		return sandboxSecurityCapabilityReadinessGateDecision(
			SandboxSecurityCapabilityReadinessGateCodeAllowed,
			SandboxSecurityCapabilityReadinessGateOutcomeAllowed,
			policyMode,
			SandboxSecurityCapabilityReadinessGateReasonReadinessReady,
			counts,
		)
	case SandboxSecurityCapabilityReadinessGatePolicyModeAdvisory:
		if counts.StrictBlocking > 0 {
			return sandboxSecurityCapabilityReadinessGateDecision(
				SandboxSecurityCapabilityReadinessGateCodeAdvisory,
				SandboxSecurityCapabilityReadinessGateOutcomeAdvisory,
				policyMode,
				SandboxSecurityCapabilityReadinessGateReasonPolicyAdvisory,
				counts,
			)
		}
		return sandboxSecurityCapabilityReadinessGateDecision(
			SandboxSecurityCapabilityReadinessGateCodeAllowed,
			SandboxSecurityCapabilityReadinessGateOutcomeAllowed,
			policyMode,
			SandboxSecurityCapabilityReadinessGateReasonReadinessReady,
			counts,
		)
	default:
		return sandboxSecurityCapabilityReadinessGateDecision(
			SandboxSecurityCapabilityReadinessGateCodeAllowed,
			SandboxSecurityCapabilityReadinessGateOutcomeAllowed,
			SandboxSecurityCapabilityReadinessGatePolicyModeOff,
			SandboxSecurityCapabilityReadinessGateReasonPolicyOff,
			counts,
		)
	}
}

func normalizeSandboxSecurityCapabilityReadinessGatePolicyMode(mode SandboxSecurityCapabilityReadinessGatePolicyMode) SandboxSecurityCapabilityReadinessGatePolicyMode {
	switch mode {
	case SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
		SandboxSecurityCapabilityReadinessGatePolicyModeAdvisory:
		return mode
	default:
		return SandboxSecurityCapabilityReadinessGatePolicyModeOff
	}
}

func sandboxSecurityCapabilityReadinessGateDecision(
	code SandboxSecurityCapabilityReadinessGateCode,
	outcome SandboxSecurityCapabilityReadinessGateOutcome,
	policyMode SandboxSecurityCapabilityReadinessGatePolicyMode,
	reason SandboxSecurityCapabilityReadinessGateReasonCode,
	counts SandboxSecurityCapabilityReadinessGateCounts,
) SandboxSecurityCapabilityReadinessGateDecision {
	return SandboxSecurityCapabilityReadinessGateDecision{
		Code:       code,
		Outcome:    outcome,
		PolicyMode: policyMode,
		Reason:     reason,
		Counts:     sandboxSecurityCapabilityReadinessGateCountsPtr(counts),
	}
}

func sandboxSecurityCapabilityReadinessGateCountsPtr(counts SandboxSecurityCapabilityReadinessGateCounts) *SandboxSecurityCapabilityReadinessGateCounts {
	if counts == (SandboxSecurityCapabilityReadinessGateCounts{}) {
		return nil
	}
	return &counts
}

func sandboxSecurityCapabilityReadinessGateCounts(diagnostics SandboxSecurityCapabilityReadinessDiagnosticSummary) (SandboxSecurityCapabilityReadinessGateCounts, SandboxSecurityCapabilityReadinessGateReasonCode) {
	var counts SandboxSecurityCapabilityReadinessGateCounts
	reason := SandboxSecurityCapabilityReadinessGateReasonReadinessReady
	reasonPriority := 0

	for _, item := range diagnostics.Items {
		counts.Total++
		classification := sandboxSecurityCapabilityReadinessGateItemClassification(item)
		switch classification {
		case SandboxSecurityCapabilityDiagnosticClassificationReady:
			counts.Ready++
		case SandboxSecurityCapabilityDiagnosticClassificationMetadataOnly:
			counts.Advisory++
			counts.MetadataOnly++
		case SandboxSecurityCapabilityDiagnosticClassificationUnsupported:
			counts.Advisory++
			counts.Unsupported++
		case SandboxSecurityCapabilityDiagnosticClassificationBlocked:
			counts.Blocked++
		case SandboxSecurityCapabilityDiagnosticClassificationReadinessMissing:
			counts.Missing++
		}
		if item.WouldBlockStrictGate {
			counts.StrictBlocking++
			if candidate, priority := sandboxSecurityCapabilityReadinessGateReason(classification); priority > reasonPriority {
				reason = candidate
				reasonPriority = priority
			}
		}
	}

	if counts.Total == 0 {
		counts.Total = 1
		counts.Missing = 1
		counts.StrictBlocking = 1
		return counts, SandboxSecurityCapabilityReadinessGateReasonReadinessMissing
	}
	if diagnostics.WouldBlockStrictGate && counts.StrictBlocking == 0 {
		counts.StrictBlocking = 1
		return counts, SandboxSecurityCapabilityReadinessGateReasonStrictBlockRequired
	}
	if counts.StrictBlocking > 0 && reasonPriority == 0 {
		return counts, SandboxSecurityCapabilityReadinessGateReasonStrictBlockRequired
	}
	return counts, reason
}

func sandboxSecurityCapabilityReadinessGateItemClassification(item SandboxSecurityCapabilityReadinessDiagnosticItem) SandboxSecurityCapabilityDiagnosticClassification {
	switch item.Classification {
	case SandboxSecurityCapabilityDiagnosticClassificationReady,
		SandboxSecurityCapabilityDiagnosticClassificationMetadataOnly,
		SandboxSecurityCapabilityDiagnosticClassificationUnsupported,
		SandboxSecurityCapabilityDiagnosticClassificationBlocked,
		SandboxSecurityCapabilityDiagnosticClassificationReadinessMissing:
		return item.Classification
	}
	switch item.Code {
	case SandboxSecurityCapabilityDiagnosticCodeReady:
		return SandboxSecurityCapabilityDiagnosticClassificationReady
	case SandboxSecurityCapabilityDiagnosticCodeMetadataOnly:
		return SandboxSecurityCapabilityDiagnosticClassificationMetadataOnly
	case SandboxSecurityCapabilityDiagnosticCodeUnsupported:
		return SandboxSecurityCapabilityDiagnosticClassificationUnsupported
	case SandboxSecurityCapabilityDiagnosticCodeBlocked:
		return SandboxSecurityCapabilityDiagnosticClassificationBlocked
	case SandboxSecurityCapabilityDiagnosticCodeReadinessMissing:
		return SandboxSecurityCapabilityDiagnosticClassificationReadinessMissing
	}
	switch item.State {
	case SandboxSecurityCapabilityReadinessReady:
		return SandboxSecurityCapabilityDiagnosticClassificationReady
	case SandboxSecurityCapabilityReadinessMetadataOnly:
		return SandboxSecurityCapabilityDiagnosticClassificationMetadataOnly
	case SandboxSecurityCapabilityReadinessUnsupported:
		return SandboxSecurityCapabilityDiagnosticClassificationUnsupported
	case SandboxSecurityCapabilityReadinessBlocked:
		return SandboxSecurityCapabilityDiagnosticClassificationBlocked
	default:
		return ""
	}
}

func sandboxSecurityCapabilityReadinessGateReason(classification SandboxSecurityCapabilityDiagnosticClassification) (SandboxSecurityCapabilityReadinessGateReasonCode, int) {
	switch classification {
	case SandboxSecurityCapabilityDiagnosticClassificationBlocked:
		return SandboxSecurityCapabilityReadinessGateReasonCapabilityBlocked, 4
	case SandboxSecurityCapabilityDiagnosticClassificationUnsupported:
		return SandboxSecurityCapabilityReadinessGateReasonCapabilityUnsupported, 3
	case SandboxSecurityCapabilityDiagnosticClassificationMetadataOnly:
		return SandboxSecurityCapabilityReadinessGateReasonMetadataOnly, 2
	case SandboxSecurityCapabilityDiagnosticClassificationReadinessMissing:
		return SandboxSecurityCapabilityReadinessGateReasonReadinessMissing, 1
	default:
		return SandboxSecurityCapabilityReadinessGateReasonStrictBlockRequired, 0
	}
}
