package sandbox

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
