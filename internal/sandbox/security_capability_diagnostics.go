package sandbox

import "sort"

// SandboxSecurityCapabilityDiagnosticCode is a stable, redaction-safe
// diagnostic identifier for readiness output.
type SandboxSecurityCapabilityDiagnosticCode string

const (
	SandboxSecurityCapabilityDiagnosticCodeReady            SandboxSecurityCapabilityDiagnosticCode = "security_capability_ready"
	SandboxSecurityCapabilityDiagnosticCodeMetadataOnly     SandboxSecurityCapabilityDiagnosticCode = "security_capability_metadata_only"
	SandboxSecurityCapabilityDiagnosticCodeUnsupported      SandboxSecurityCapabilityDiagnosticCode = "security_capability_unsupported"
	SandboxSecurityCapabilityDiagnosticCodeBlocked          SandboxSecurityCapabilityDiagnosticCode = "security_capability_blocked"
	SandboxSecurityCapabilityDiagnosticCodeReadinessMissing SandboxSecurityCapabilityDiagnosticCode = "security_capability_readiness_missing"
)

// SandboxSecurityCapabilityDiagnosticSeverity is a stable severity label for
// advisory security readiness diagnostics.
type SandboxSecurityCapabilityDiagnosticSeverity string

const (
	SandboxSecurityCapabilityDiagnosticSeverityInfo    SandboxSecurityCapabilityDiagnosticSeverity = "info"
	SandboxSecurityCapabilityDiagnosticSeverityWarning SandboxSecurityCapabilityDiagnosticSeverity = "warning"
	SandboxSecurityCapabilityDiagnosticSeverityError   SandboxSecurityCapabilityDiagnosticSeverity = "error"
)

// SandboxSecurityCapabilityDiagnosticClassification groups diagnostics by
// conservative readiness outcome using enum-like metadata only.
type SandboxSecurityCapabilityDiagnosticClassification string

const (
	SandboxSecurityCapabilityDiagnosticClassificationReady            SandboxSecurityCapabilityDiagnosticClassification = "capability_ready"
	SandboxSecurityCapabilityDiagnosticClassificationMetadataOnly     SandboxSecurityCapabilityDiagnosticClassification = "metadata_only"
	SandboxSecurityCapabilityDiagnosticClassificationUnsupported      SandboxSecurityCapabilityDiagnosticClassification = "capability_unsupported"
	SandboxSecurityCapabilityDiagnosticClassificationBlocked          SandboxSecurityCapabilityDiagnosticClassification = "capability_blocked"
	SandboxSecurityCapabilityDiagnosticClassificationReadinessMissing SandboxSecurityCapabilityDiagnosticClassification = "readiness_missing"
)

// SandboxSecurityCapabilityDiagnosticSummaryStatus is the aggregate diagnostic
// status for a readiness diagnostic summary.
type SandboxSecurityCapabilityDiagnosticSummaryStatus string

const (
	SandboxSecurityCapabilityDiagnosticSummaryStatusUnknown  SandboxSecurityCapabilityDiagnosticSummaryStatus = "unknown"
	SandboxSecurityCapabilityDiagnosticSummaryStatusReady    SandboxSecurityCapabilityDiagnosticSummaryStatus = "ready"
	SandboxSecurityCapabilityDiagnosticSummaryStatusAdvisory SandboxSecurityCapabilityDiagnosticSummaryStatus = "advisory"
	SandboxSecurityCapabilityDiagnosticSummaryStatusBlocked  SandboxSecurityCapabilityDiagnosticSummaryStatus = "blocked"
)

// SandboxSecurityCapabilityReadinessDiagnosticSummary is an additive,
// advisory-only diagnostic surface for capability readiness output. It carries
// only safe labels and aggregate counts.
type SandboxSecurityCapabilityReadinessDiagnosticSummary struct {
	Status               SandboxSecurityCapabilityDiagnosticSummaryStatus   `json:"status"`
	Total                int                                                `json:"total,omitempty"`
	HighestSeverity      SandboxSecurityCapabilityDiagnosticSeverity        `json:"highestSeverity,omitempty"`
	AdvisoryOnly         bool                                               `json:"advisoryOnly"`
	WouldBlockStrictGate bool                                               `json:"wouldBlockStrictGate"`
	Items                []SandboxSecurityCapabilityReadinessDiagnosticItem `json:"items,omitempty"`
}

// SandboxSecurityCapabilityReadinessDiagnosticItem is one additive,
// redaction-safe advisory diagnostic derived from capability readiness output.
type SandboxSecurityCapabilityReadinessDiagnosticItem struct {
	Code                 SandboxSecurityCapabilityDiagnosticCode           `json:"code"`
	Severity             SandboxSecurityCapabilityDiagnosticSeverity       `json:"severity"`
	Classification       SandboxSecurityCapabilityDiagnosticClassification `json:"classification"`
	AdvisoryOnly         bool                                              `json:"advisoryOnly"`
	WouldBlockStrictGate bool                                              `json:"wouldBlockStrictGate"`
	State                SandboxSecurityCapabilityReadinessState           `json:"state,omitempty"`
	Family               SandboxSecurityCapabilityFamily                   `json:"family,omitempty"`
	Capability           SandboxSecurityCapabilityName                     `json:"capability,omitempty"`
	ReasonCode           SandboxSecurityCapabilityReasonCode               `json:"reasonCode,omitempty"`
	WarningCodes         []SandboxSecurityCapabilityWarningCode            `json:"warningCodes,omitempty"`
}

// DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary converts sanitized
// readiness output into deterministic advisory diagnostics. It sanitizes again
// defensively and returns newly constructed values.
func DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(output SandboxSecurityCapabilityReadinessOutput) SandboxSecurityCapabilityReadinessDiagnosticSummary {
	output = SanitizeSandboxSecurityCapabilityReadinessOutput(output)
	if len(output.Results) == 0 {
		return sandboxSecurityCapabilityReadinessMissingDiagnosticSummary()
	}

	items := make([]SandboxSecurityCapabilityReadinessDiagnosticItem, 0, len(output.Results))
	for _, result := range output.Results {
		item, ok := sandboxSecurityCapabilityReadinessDiagnosticItem(result)
		if ok {
			items = append(items, item)
		}
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

// DeriveSandboxSecurityCapabilityReadinessDiagnosticSummaryPtr returns nil
// when readiness is nil or sanitizes to no results. It is intended for
// additive metadata clone paths that should only surface diagnostics from an
// approved readiness surface.
func DeriveSandboxSecurityCapabilityReadinessDiagnosticSummaryPtr(output *SandboxSecurityCapabilityReadinessOutput) *SandboxSecurityCapabilityReadinessDiagnosticSummary {
	output = CloneSandboxSecurityCapabilityReadinessOutputPtr(output)
	if output == nil {
		return nil
	}
	summary := DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(*output)
	return &summary
}

func sandboxSecurityCapabilityReadinessMissingDiagnosticSummary() SandboxSecurityCapabilityReadinessDiagnosticSummary {
	item := SandboxSecurityCapabilityReadinessDiagnosticItem{
		Code:                 SandboxSecurityCapabilityDiagnosticCodeReadinessMissing,
		Severity:             SandboxSecurityCapabilityDiagnosticSeverityWarning,
		Classification:       SandboxSecurityCapabilityDiagnosticClassificationReadinessMissing,
		AdvisoryOnly:         true,
		WouldBlockStrictGate: true,
	}
	return SandboxSecurityCapabilityReadinessDiagnosticSummary{
		Status:               SandboxSecurityCapabilityDiagnosticSummaryStatusUnknown,
		Total:                1,
		HighestSeverity:      SandboxSecurityCapabilityDiagnosticSeverityWarning,
		AdvisoryOnly:         true,
		WouldBlockStrictGate: true,
		Items:                []SandboxSecurityCapabilityReadinessDiagnosticItem{item},
	}
}

func sandboxSecurityCapabilityReadinessDiagnosticItem(result SandboxSecurityCapabilityReadinessResult) (SandboxSecurityCapabilityReadinessDiagnosticItem, bool) {
	item := SandboxSecurityCapabilityReadinessDiagnosticItem{
		AdvisoryOnly: true,
		State:        result.State,
	}
	var context *SandboxSecurityCapabilityMetadata
	var warningGroups [][]SandboxSecurityCapabilityWarningCode
	switch result.State {
	case SandboxSecurityCapabilityReadinessReady:
		item.Code = SandboxSecurityCapabilityDiagnosticCodeReady
		item.Severity = SandboxSecurityCapabilityDiagnosticSeverityInfo
		item.Classification = SandboxSecurityCapabilityDiagnosticClassificationReady
		item.WouldBlockStrictGate = false
		item.ReasonCode = sandboxSecurityCapabilityDiagnosticReasonCode(
			SandboxSecurityCapabilityReasonCapabilityConfirmed,
			result.ReasonCode,
			sandboxSecurityCapabilityDiagnosticMetadataReasonCode(result.Requested),
			sandboxSecurityCapabilityDiagnosticMetadataReasonCode(result.Ready),
		)
		context = result.Requested
		warningGroups = [][]SandboxSecurityCapabilityWarningCode{
			result.WarningCodes,
			sandboxSecurityCapabilityDiagnosticMetadataWarningCodes(result.Requested),
			sandboxSecurityCapabilityDiagnosticMetadataWarningCodes(result.Ready),
		}
	case SandboxSecurityCapabilityReadinessMetadataOnly:
		item.Code = SandboxSecurityCapabilityDiagnosticCodeMetadataOnly
		item.Severity = SandboxSecurityCapabilityDiagnosticSeverityWarning
		item.Classification = SandboxSecurityCapabilityDiagnosticClassificationMetadataOnly
		item.WouldBlockStrictGate = true
		item.ReasonCode = sandboxSecurityCapabilityDiagnosticReasonCode(
			SandboxSecurityCapabilityReasonMetadataOnly,
			result.ReasonCode,
			sandboxSecurityCapabilityDiagnosticMetadataReasonCode(result.Metadata),
		)
		context = result.Metadata
		warningGroups = [][]SandboxSecurityCapabilityWarningCode{
			result.WarningCodes,
			sandboxSecurityCapabilityDiagnosticMetadataWarningCodes(result.Metadata),
		}
	case SandboxSecurityCapabilityReadinessUnsupported:
		item.Code = SandboxSecurityCapabilityDiagnosticCodeUnsupported
		item.Severity = SandboxSecurityCapabilityDiagnosticSeverityWarning
		item.Classification = SandboxSecurityCapabilityDiagnosticClassificationUnsupported
		item.WouldBlockStrictGate = true
		item.ReasonCode = sandboxSecurityCapabilityDiagnosticReasonCode(
			SandboxSecurityCapabilityReasonCapabilityMissing,
			result.ReasonCode,
			sandboxSecurityCapabilityDiagnosticMetadataReasonCode(result.Requested),
		)
		context = result.Requested
		warningGroups = [][]SandboxSecurityCapabilityWarningCode{
			result.WarningCodes,
			sandboxSecurityCapabilityDiagnosticMetadataWarningCodes(result.Requested),
		}
	case SandboxSecurityCapabilityReadinessBlocked:
		item.Code = SandboxSecurityCapabilityDiagnosticCodeBlocked
		item.Severity = SandboxSecurityCapabilityDiagnosticSeverityWarning
		item.Classification = SandboxSecurityCapabilityDiagnosticClassificationBlocked
		item.WouldBlockStrictGate = true
		item.ReasonCode = sandboxSecurityCapabilityDiagnosticReasonCode(
			SandboxSecurityCapabilityReasonCapabilityBlocked,
			result.ReasonCode,
			sandboxSecurityCapabilityDiagnosticMetadataReasonCode(result.Requested),
			sandboxSecurityCapabilityDiagnosticMetadataReasonCode(result.Ready),
		)
		context = result.Requested
		warningGroups = [][]SandboxSecurityCapabilityWarningCode{
			result.WarningCodes,
			sandboxSecurityCapabilityDiagnosticMetadataWarningCodes(result.Requested),
			sandboxSecurityCapabilityDiagnosticMetadataWarningCodes(result.Ready),
		}
	default:
		return SandboxSecurityCapabilityReadinessDiagnosticItem{}, false
	}
	if context == nil {
		return SandboxSecurityCapabilityReadinessDiagnosticItem{}, false
	}
	item.Family = context.Family
	item.Capability = context.Capability
	item.WarningCodes = sandboxSecurityCapabilityDiagnosticWarningCodes(warningGroups...)
	return item, true
}

func sandboxSecurityCapabilityDiagnosticReasonCode(defaultReason SandboxSecurityCapabilityReasonCode, reasons ...SandboxSecurityCapabilityReasonCode) SandboxSecurityCapabilityReasonCode {
	for _, reason := range reasons {
		reason = sanitizeSandboxSecurityCapabilityReasonCodeValue(reason)
		if reason != "" {
			return reason
		}
	}
	return defaultReason
}

func sandboxSecurityCapabilityDiagnosticMetadataReasonCode(metadata *SandboxSecurityCapabilityMetadata) SandboxSecurityCapabilityReasonCode {
	if metadata == nil {
		return ""
	}
	return metadata.ReasonCode
}

func sandboxSecurityCapabilityDiagnosticMetadataWarningCodes(metadata *SandboxSecurityCapabilityMetadata) []SandboxSecurityCapabilityWarningCode {
	if metadata == nil {
		return nil
	}
	return metadata.WarningCodes
}

func sandboxSecurityCapabilityDiagnosticWarningCodes(groups ...[]SandboxSecurityCapabilityWarningCode) []SandboxSecurityCapabilityWarningCode {
	seen := make(map[SandboxSecurityCapabilityWarningCode]bool)
	var warnings []SandboxSecurityCapabilityWarningCode
	for _, group := range groups {
		for _, warning := range group {
			warning = sanitizeSandboxSecurityCapabilityWarningCodeValue(warning)
			if warning == "" || seen[warning] {
				continue
			}
			seen[warning] = true
			warnings = append(warnings, warning)
		}
	}
	if len(warnings) == 0 {
		return nil
	}
	sort.Slice(warnings, func(i, j int) bool {
		return warnings[i] < warnings[j]
	})
	return warnings
}

func sandboxSecurityCapabilityReadinessDiagnosticSummaryStatus(items []SandboxSecurityCapabilityReadinessDiagnosticItem) SandboxSecurityCapabilityDiagnosticSummaryStatus {
	allReady := true
	for _, item := range items {
		switch item.Classification {
		case SandboxSecurityCapabilityDiagnosticClassificationBlocked:
			return SandboxSecurityCapabilityDiagnosticSummaryStatusBlocked
		case SandboxSecurityCapabilityDiagnosticClassificationReady:
		default:
			allReady = false
		}
	}
	if allReady {
		return SandboxSecurityCapabilityDiagnosticSummaryStatusReady
	}
	return SandboxSecurityCapabilityDiagnosticSummaryStatusAdvisory
}

func sandboxSecurityCapabilityReadinessDiagnosticHighestSeverity(items []SandboxSecurityCapabilityReadinessDiagnosticItem) SandboxSecurityCapabilityDiagnosticSeverity {
	highest := SandboxSecurityCapabilityDiagnosticSeverityInfo
	for _, item := range items {
		if sandboxSecurityCapabilityDiagnosticSeverityRank(item.Severity) > sandboxSecurityCapabilityDiagnosticSeverityRank(highest) {
			highest = item.Severity
		}
	}
	return highest
}

func sandboxSecurityCapabilityReadinessDiagnosticsWouldBlockStrictGate(items []SandboxSecurityCapabilityReadinessDiagnosticItem) bool {
	for _, item := range items {
		if item.WouldBlockStrictGate {
			return true
		}
	}
	return false
}

func sandboxSecurityCapabilityReadinessDiagnosticItemLess(a, b SandboxSecurityCapabilityReadinessDiagnosticItem) bool {
	if ap, bp := sandboxSecurityCapabilityDiagnosticClassificationPriority(a.Classification), sandboxSecurityCapabilityDiagnosticClassificationPriority(b.Classification); ap != bp {
		return ap < bp
	}
	if a.Family != b.Family {
		return a.Family < b.Family
	}
	if a.Capability != b.Capability {
		return a.Capability < b.Capability
	}
	if a.ReasonCode != b.ReasonCode {
		return a.ReasonCode < b.ReasonCode
	}
	if a.Code != b.Code {
		return a.Code < b.Code
	}
	if a.State != b.State {
		return a.State < b.State
	}
	if a.Severity != b.Severity {
		return a.Severity < b.Severity
	}
	return sandboxSecurityCapabilityDiagnosticWarningCodesLess(a.WarningCodes, b.WarningCodes)
}

func sandboxSecurityCapabilityDiagnosticClassificationPriority(classification SandboxSecurityCapabilityDiagnosticClassification) int {
	switch classification {
	case SandboxSecurityCapabilityDiagnosticClassificationBlocked:
		return 0
	case SandboxSecurityCapabilityDiagnosticClassificationUnsupported:
		return 1
	case SandboxSecurityCapabilityDiagnosticClassificationMetadataOnly:
		return 2
	case SandboxSecurityCapabilityDiagnosticClassificationReadinessMissing:
		return 3
	case SandboxSecurityCapabilityDiagnosticClassificationReady:
		return 4
	default:
		return 5
	}
}

func sandboxSecurityCapabilityDiagnosticSeverityRank(severity SandboxSecurityCapabilityDiagnosticSeverity) int {
	switch severity {
	case SandboxSecurityCapabilityDiagnosticSeverityError:
		return 3
	case SandboxSecurityCapabilityDiagnosticSeverityWarning:
		return 2
	case SandboxSecurityCapabilityDiagnosticSeverityInfo:
		return 1
	default:
		return 0
	}
}

func sandboxSecurityCapabilityDiagnosticWarningCodesLess(a, b []SandboxSecurityCapabilityWarningCode) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}
