package sandbox

import "sort"

// EvaluateSandboxSecureDefaultReadiness applies the strict secure-default
// evidence policy to sanitized capability readiness output.
func EvaluateSandboxSecureDefaultReadiness(output SandboxSecurityCapabilityReadinessOutput) SandboxSecurityCapabilityReadinessGateDecision {
	return EvaluateSandboxSecurityCapabilityReadinessGate(
		SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
		ProjectSandboxSecureDefaultReadinessDiagnostics(output),
	)
}

// ProjectSandboxSecureDefaultReadinessDiagnostics classifies complete versus
// incomplete secure-default evidence using only sanitized readiness metadata.
func ProjectSandboxSecureDefaultReadinessDiagnostics(output SandboxSecurityCapabilityReadinessOutput) SandboxSecurityCapabilityReadinessDiagnosticSummary {
	output = SanitizeSandboxSecurityCapabilityReadinessOutput(output)
	if len(output.Results) == 0 {
		return sandboxSecurityCapabilityReadinessMissingDiagnosticSummary()
	}

	items := make([]SandboxSecurityCapabilityReadinessDiagnosticItem, 0, len(output.Results))
	for _, result := range output.Results {
		item, ok := sandboxSecurityCapabilityReadinessDiagnosticItem(result)
		if !ok {
			continue
		}
		if sandboxSecureDefaultReadinessResultWarningBearing(result, item) {
			item = sandboxSecureDefaultWarningBearingDiagnosticItem(item)
		}
		items = append(items, item)
	}
	if len(items) == 0 {
		return sandboxSecurityCapabilityReadinessMissingDiagnosticSummary()
	}

	sort.SliceStable(items, func(i, j int) bool {
		return sandboxSecurityCapabilityReadinessDiagnosticItemLess(items[i], items[j])
	})

	return SandboxSecurityCapabilityReadinessDiagnosticSummary{
		Status:               sandboxSecurityCapabilityReadinessDiagnosticSummaryStatus(items),
		Total:                len(items),
		HighestSeverity:      sandboxSecurityCapabilityReadinessDiagnosticHighestSeverity(items),
		AdvisoryOnly:         true,
		WouldBlockStrictGate: sandboxSecurityCapabilityReadinessDiagnosticsWouldBlockStrictGate(items),
		Items:                items,
	}
}

func sandboxSecureDefaultReadinessResultWarningBearing(result SandboxSecurityCapabilityReadinessResult, item SandboxSecurityCapabilityReadinessDiagnosticItem) bool {
	if result.State != SandboxSecurityCapabilityReadinessReady {
		return false
	}
	return len(item.WarningCodes) > 0
}

func sandboxSecureDefaultWarningBearingDiagnosticItem(item SandboxSecurityCapabilityReadinessDiagnosticItem) SandboxSecurityCapabilityReadinessDiagnosticItem {
	item.Code = SandboxSecurityCapabilityDiagnosticCodeUnsupported
	item.Severity = SandboxSecurityCapabilityDiagnosticSeverityWarning
	item.Classification = SandboxSecurityCapabilityDiagnosticClassificationUnsupported
	item.WouldBlockStrictGate = true
	item.ReasonCode = SandboxSecurityCapabilityReasonWarningBearing
	return item
}
