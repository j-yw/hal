package sandbox

// SandboxSecurityCapabilityReadinessGatePolicyMode is the opt-in policy mode
// for readiness gate decisions.
type SandboxSecurityCapabilityReadinessGatePolicyMode string

const (
	SandboxSecurityCapabilityReadinessGatePolicyModeOff           SandboxSecurityCapabilityReadinessGatePolicyMode = "off"
	SandboxSecurityCapabilityReadinessGatePolicyModeCompatibility SandboxSecurityCapabilityReadinessGatePolicyMode = "compatibility"
	SandboxSecurityCapabilityReadinessGatePolicyModeAdvisory      SandboxSecurityCapabilityReadinessGatePolicyMode = "advisory"
	SandboxSecurityCapabilityReadinessGatePolicyModeStrict        SandboxSecurityCapabilityReadinessGatePolicyMode = "strict"
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
	SandboxSecurityCapabilityReadinessGateReasonPolicyCompatibility   SandboxSecurityCapabilityReadinessGateReasonCode = "policy_compatibility"
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
	Total            int                                         `json:"total,omitempty"`
	Ready            int                                         `json:"ready,omitempty"`
	Advisory         int                                         `json:"advisory,omitempty"`
	Blocked          int                                         `json:"blocked,omitempty"`
	Missing          int                                         `json:"missing,omitempty"`
	MetadataOnly     int                                         `json:"metadataOnly,omitempty"`
	Unsupported      int                                         `json:"unsupported,omitempty"`
	StrictBlocking   int                                         `json:"strictBlocking,omitempty"`
	ReasonCodeCounts map[SandboxSecurityCapabilityReasonCode]int `json:"reasonCodeCounts,omitempty"`
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

// EvaluateSandboxSecurityCapabilityReadinessGateFromDiagnosticsPtr evaluates
// optional diagnostic metadata. Nil diagnostics are treated as missing
// readiness, so only explicit strict mode can block.
func EvaluateSandboxSecurityCapabilityReadinessGateFromDiagnosticsPtr(mode SandboxSecurityCapabilityReadinessGatePolicyMode, diagnostics *SandboxSecurityCapabilityReadinessDiagnosticSummary) SandboxSecurityCapabilityReadinessGateDecision {
	if diagnostics == nil {
		return EvaluateSandboxSecurityCapabilityReadinessGate(mode, SandboxSecurityCapabilityReadinessDiagnosticSummary{})
	}
	return EvaluateSandboxSecurityCapabilityReadinessGate(mode, *diagnostics)
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
	case SandboxSecurityCapabilityReadinessGatePolicyModeCompatibility:
		if counts.StrictBlocking > 0 {
			return sandboxSecurityCapabilityReadinessGateDecision(
				SandboxSecurityCapabilityReadinessGateCodeAdvisory,
				SandboxSecurityCapabilityReadinessGateOutcomeAdvisory,
				policyMode,
				SandboxSecurityCapabilityReadinessGateReasonPolicyCompatibility,
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
		SandboxSecurityCapabilityReadinessGatePolicyModeCompatibility,
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
	if counts.Total == 0 &&
		counts.Ready == 0 &&
		counts.Advisory == 0 &&
		counts.Blocked == 0 &&
		counts.Missing == 0 &&
		counts.MetadataOnly == 0 &&
		counts.Unsupported == 0 &&
		counts.StrictBlocking == 0 &&
		len(counts.ReasonCodeCounts) == 0 {
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
			if candidate, priority := sandboxSecurityCapabilityReadinessGateStrictReason(item, classification); priority > reasonPriority {
				reason = candidate
				reasonPriority = priority
			}
		}
		sandboxSecurityCapabilityReadinessGateIncrementReasonCode(&counts, sandboxSecurityCapabilityReadinessGateItemReasonCode(item, classification))
	}

	if counts.Total == 0 {
		counts.Total = 1
		counts.Missing = 1
		counts.StrictBlocking = 1
		sandboxSecurityCapabilityReadinessGateIncrementReasonCode(&counts, SandboxSecurityCapabilityReasonReadinessMissing)
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

func sandboxSecurityCapabilityReadinessGateIncrementReasonCode(counts *SandboxSecurityCapabilityReadinessGateCounts, reason SandboxSecurityCapabilityReasonCode) {
	reason = sanitizeSandboxSecurityCapabilityReasonCodeValue(reason)
	if reason == "" {
		return
	}
	if counts.ReasonCodeCounts == nil {
		counts.ReasonCodeCounts = make(map[SandboxSecurityCapabilityReasonCode]int)
	}
	counts.ReasonCodeCounts[reason]++
}

func sandboxSecurityCapabilityReadinessGateItemReasonCode(item SandboxSecurityCapabilityReadinessDiagnosticItem, classification SandboxSecurityCapabilityDiagnosticClassification) SandboxSecurityCapabilityReasonCode {
	if reason := sanitizeSandboxSecurityCapabilityReasonCodeValue(item.ReasonCode); reason != "" {
		return reason
	}
	switch classification {
	case SandboxSecurityCapabilityDiagnosticClassificationReady:
		return SandboxSecurityCapabilityReasonCapabilityConfirmed
	case SandboxSecurityCapabilityDiagnosticClassificationMetadataOnly:
		return SandboxSecurityCapabilityReasonMetadataOnly
	case SandboxSecurityCapabilityDiagnosticClassificationUnsupported:
		return SandboxSecurityCapabilityReasonCapabilityMissing
	case SandboxSecurityCapabilityDiagnosticClassificationBlocked:
		return SandboxSecurityCapabilityReasonCapabilityBlocked
	case SandboxSecurityCapabilityDiagnosticClassificationReadinessMissing:
		return SandboxSecurityCapabilityReasonReadinessMissing
	default:
		return ""
	}
}

func sandboxSecurityCapabilityReadinessGateStrictReason(item SandboxSecurityCapabilityReadinessDiagnosticItem, classification SandboxSecurityCapabilityDiagnosticClassification) (SandboxSecurityCapabilityReadinessGateReasonCode, int) {
	fallback, priority := sandboxSecurityCapabilityReadinessGateReason(classification)
	if reason := sandboxSecurityCapabilityReadinessGateItemReasonCode(item, classification); reason != "" {
		return SandboxSecurityCapabilityReadinessGateReasonCode(reason), priority
	}
	return fallback, priority
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
