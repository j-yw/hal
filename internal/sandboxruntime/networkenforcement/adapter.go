package networkenforcement

import (
	"context"
	"encoding/json"
)

// Adapter is the narrow runtime-owned boundary for future live network
// enforcement implementations. Implementations receive a sanitized plan and
// return metadata only; they must not expose listener details, firewall rule
// bodies, process handles, credentials, or raw network destinations.
type Adapter interface {
	EnforceNetwork(context.Context, SanitizedPlan) Result
}

// SanitizedPlan wraps a redaction-safe enforcement plan before it reaches an
// adapter. The contained plan is intentionally not settable by callers outside
// this package.
type SanitizedPlan struct {
	plan Plan
}

// NewSanitizedPlan returns a redaction-safe adapter input plan.
func NewSanitizedPlan(plan Plan) SanitizedPlan {
	return SanitizedPlan{plan: SanitizePlan(plan)}
}

// Plan returns a redaction-safe copy of the adapter input plan.
func (p SanitizedPlan) Plan() Plan {
	return SanitizePlan(p.plan)
}

// MarshalJSON keeps adapter input JSON redaction-safe when callers include a
// sanitized plan in test metadata or diagnostics.
func (p SanitizedPlan) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.Plan())
}

// RunAdapter sanitizes adapter input and output while keeping nil adapters on
// the safe unsupported path.
func RunAdapter(ctx context.Context, adapter Adapter, plan Plan) Result {
	sanitizedPlan := NewSanitizedPlan(plan)
	input := sanitizedPlan.Plan()
	if adapter == nil {
		return SanitizeResult(Result{
			PlanID:          input.ID,
			Outcome:         ResultOutcomeUnsupported,
			EnforcementMode: ResultModeNone,
			ReasonCode:      ResultReasonAdapterUnsupported,
		})
	}

	result := SanitizeResult(adapter.EnforceNetwork(ctx, sanitizedPlan))
	if result.PlanID == "" {
		result.PlanID = input.ID
	}
	return SanitizeResult(result)
}

// ResultOutcome identifies the sanitized adapter outcome.
type ResultOutcome string

const (
	ResultOutcomeSuccess     ResultOutcome = "success"
	ResultOutcomeBestEffort  ResultOutcome = "best_effort"
	ResultOutcomeUnsupported ResultOutcome = "unsupported"
	ResultOutcomeFailure     ResultOutcome = "failure"
)

// ResultMode mirrors durable network enforcement labels without importing
// sandbox policy packages.
type ResultMode string

const (
	ResultModeNone          ResultMode = "none"
	ResultModeBestEffort    ResultMode = "best_effort"
	ResultModeProxy         ResultMode = "proxy"
	ResultModeFirewall      ResultMode = "firewall"
	ResultModeRuntime       ResultMode = "runtime"
	ResultModeProxyFirewall ResultMode = "proxy_firewall"
)

// ResultReasonCode is a redaction-safe explanation for adapter outcomes.
type ResultReasonCode string

const (
	ResultReasonApplied            ResultReasonCode = "applied"
	ResultReasonBestEffort         ResultReasonCode = "best_effort"
	ResultReasonAdapterUnsupported ResultReasonCode = "adapter_unsupported"
	ResultReasonAdapterFailed      ResultReasonCode = "adapter_failed"
	ResultReasonCapabilityMissing  ResultReasonCode = "capability_missing"
	ResultReasonModeUnavailable    ResultReasonCode = "mode_unavailable"
)

// ResultWarningCode is a redaction-safe warning label for adapter metadata.
type ResultWarningCode string

const (
	ResultWarningPartialEnforcement    ResultWarningCode = "partial_enforcement"
	ResultWarningUnsupportedMode       ResultWarningCode = "unsupported_mode"
	ResultWarningCapabilityDowngraded  ResultWarningCode = "capability_downgraded"
	ResultWarningMetadataOnlyFallback  ResultWarningCode = "metadata_only_fallback"
	ResultWarningSanitizedAdapterError ResultWarningCode = "sanitized_adapter_error"
)

// Result records only redaction-safe enforcement metadata returned by an
// adapter.
type Result struct {
	PlanID          string                  `json:"planId,omitempty"`
	AdapterID       string                  `json:"adapterId,omitempty"`
	Outcome         ResultOutcome           `json:"outcome,omitempty"`
	EnforcementMode ResultMode              `json:"enforcementMode,omitempty"`
	Mechanisms      []EnforcementMechanism  `json:"mechanisms,omitempty"`
	Operations      []string                `json:"operations,omitempty"`
	PolicySnapshot  *PolicySnapshotIdentity `json:"policySnapshot,omitempty"`
	Capability      *ResultCapability       `json:"capability,omitempty"`
	ReasonCode      ResultReasonCode        `json:"reasonCode,omitempty"`
	WarningCodes    []ResultWarningCode     `json:"warningCodes,omitempty"`
}

// ResultCapability captures the policy-shape capabilities proven by an
// adapter result using enum-like metadata only.
type ResultCapability struct {
	Supported                  bool         `json:"supported,omitempty"`
	Modes                      []ResultMode `json:"modes,omitempty"`
	SupportsDomainRules        bool         `json:"supportsDomainRules,omitempty"`
	SupportsEndpointRules      bool         `json:"supportsEndpointRules,omitempty"`
	SupportsPrivateRangeRules  bool         `json:"supportsPrivateRangeRules,omitempty"`
	SupportsMetadataEndpoint   bool         `json:"supportsMetadataEndpoint,omitempty"`
	SupportsLoopbackRules      bool         `json:"supportsLoopbackRules,omitempty"`
	SupportsLinkLocalRules     bool         `json:"supportsLinkLocalRules,omitempty"`
	SupportsDefaultDenyPosture bool         `json:"supportsDefaultDenyPosture,omitempty"`
}

// SanitizeResult returns a redaction-safe copy of adapter metadata. Failure
// and unsupported outcomes fail closed by clearing enforcing modes and
// capability claims.
func SanitizeResult(result Result) Result {
	outcome := sanitizeResultOutcome(result.Outcome)
	mode := sanitizeResultMode(result.EnforcementMode)
	if outcome == "" && resultModeCanEnforce(mode) {
		outcome = ResultOutcomeSuccess
	}
	if outcome == "" && mode == ResultModeBestEffort {
		outcome = ResultOutcomeBestEffort
	}
	if outcome == "" {
		outcome = ResultOutcomeUnsupported
	}

	sanitized := Result{
		PlanID:          sanitizeIdentifier(result.PlanID),
		AdapterID:       sanitizeIdentifier(result.AdapterID),
		Outcome:         outcome,
		EnforcementMode: sanitizeResultModeForOutcome(outcome, mode),
		Mechanisms:      sanitizeEnforcementMechanismList(result.Mechanisms),
		Operations:      sanitizeIdentifierList(result.Operations),
		PolicySnapshot:  sanitizePolicySnapshotIdentityPtr(result.PolicySnapshot),
		Capability:      sanitizeResultCapabilityPtr(result.Capability),
		ReasonCode:      sanitizeResultReasonCode(result.ReasonCode),
		WarningCodes:    sanitizeResultWarningCodeList(result.WarningCodes),
	}

	switch outcome {
	case ResultOutcomeFailure:
		sanitized.Capability = nil
		sanitized.ReasonCode = defaultResultReasonCode(sanitized.ReasonCode, ResultReasonAdapterFailed)
	case ResultOutcomeUnsupported:
		sanitized.Capability = nil
		sanitized.ReasonCode = defaultResultReasonCode(sanitized.ReasonCode, ResultReasonAdapterUnsupported)
	case ResultOutcomeBestEffort:
		sanitized.ReasonCode = defaultResultReasonCode(sanitized.ReasonCode, ResultReasonBestEffort)
	default:
		sanitized.ReasonCode = defaultResultReasonCode(sanitized.ReasonCode, ResultReasonApplied)
	}

	return sanitized
}

// MarshalJSON keeps public result JSON sanitized even when callers pass
// unsanitized contract values directly to encoding/json.
func (r Result) MarshalJSON() ([]byte, error) {
	type resultJSON Result
	sanitized := SanitizeResult(r)
	return json.Marshal(resultJSON(sanitized))
}

func (c ResultCapability) MarshalJSON() ([]byte, error) {
	type resultCapabilityJSON ResultCapability
	sanitized := sanitizeResultCapability(c)
	return json.Marshal(resultCapabilityJSON(sanitized))
}

func sanitizeResultOutcome(value ResultOutcome) ResultOutcome {
	normalized := ResultOutcome(normalizeEnum(string(value)))
	switch normalized {
	case ResultOutcomeSuccess,
		ResultOutcomeBestEffort,
		ResultOutcomeUnsupported,
		ResultOutcomeFailure:
		return normalized
	default:
		return ""
	}
}

func sanitizeResultMode(value ResultMode) ResultMode {
	normalized := ResultMode(normalizeEnum(string(value)))
	switch normalized {
	case ResultModeNone,
		ResultModeBestEffort,
		ResultModeProxy,
		ResultModeFirewall,
		ResultModeRuntime,
		ResultModeProxyFirewall:
		return normalized
	default:
		return ""
	}
}

func sanitizeResultModeForOutcome(outcome ResultOutcome, mode ResultMode) ResultMode {
	switch outcome {
	case ResultOutcomeSuccess:
		if resultModeCanEnforce(mode) {
			return mode
		}
		return ResultModeNone
	case ResultOutcomeBestEffort:
		return ResultModeBestEffort
	case ResultOutcomeUnsupported, ResultOutcomeFailure:
		return ResultModeNone
	default:
		return ""
	}
}

func resultModeCanEnforce(mode ResultMode) bool {
	switch mode {
	case ResultModeProxy,
		ResultModeFirewall,
		ResultModeRuntime,
		ResultModeProxyFirewall:
		return true
	default:
		return false
	}
}

func sanitizeResultReasonCode(value ResultReasonCode) ResultReasonCode {
	normalized := ResultReasonCode(normalizeEnum(string(value)))
	switch normalized {
	case ResultReasonApplied,
		ResultReasonBestEffort,
		ResultReasonAdapterUnsupported,
		ResultReasonAdapterFailed,
		ResultReasonCapabilityMissing,
		ResultReasonModeUnavailable:
		return normalized
	default:
		return ""
	}
}

func defaultResultReasonCode(value, fallback ResultReasonCode) ResultReasonCode {
	if value != "" {
		return value
	}
	return fallback
}

func sanitizeResultWarningCode(value ResultWarningCode) ResultWarningCode {
	normalized := ResultWarningCode(normalizeEnum(string(value)))
	switch normalized {
	case ResultWarningPartialEnforcement,
		ResultWarningUnsupportedMode,
		ResultWarningCapabilityDowngraded,
		ResultWarningMetadataOnlyFallback,
		ResultWarningSanitizedAdapterError:
		return normalized
	default:
		return ""
	}
}

func sanitizeResultWarningCodeList(values []ResultWarningCode) []ResultWarningCode {
	if len(values) == 0 {
		return nil
	}
	sanitized := make([]ResultWarningCode, 0, len(values))
	for _, value := range values {
		if current := sanitizeResultWarningCode(value); current != "" {
			sanitized = append(sanitized, current)
		}
	}
	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
}

func sanitizeEnforcementMechanismList(values []EnforcementMechanism) []EnforcementMechanism {
	if len(values) == 0 {
		return nil
	}
	sanitized := make([]EnforcementMechanism, 0, len(values))
	for _, value := range values {
		if current := sanitizeEnforcementMechanism(value); current != "" {
			sanitized = append(sanitized, current)
		}
	}
	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
}

func sanitizeResultCapabilityPtr(capability *ResultCapability) *ResultCapability {
	if capability == nil {
		return nil
	}
	sanitized := sanitizeResultCapability(*capability)
	if resultCapabilityEmpty(sanitized) {
		return nil
	}
	return &sanitized
}

func sanitizeResultCapability(capability ResultCapability) ResultCapability {
	return ResultCapability{
		Supported:                  capability.Supported,
		Modes:                      sanitizeResultModeList(capability.Modes),
		SupportsDomainRules:        capability.SupportsDomainRules,
		SupportsEndpointRules:      capability.SupportsEndpointRules,
		SupportsPrivateRangeRules:  capability.SupportsPrivateRangeRules,
		SupportsMetadataEndpoint:   capability.SupportsMetadataEndpoint,
		SupportsLoopbackRules:      capability.SupportsLoopbackRules,
		SupportsLinkLocalRules:     capability.SupportsLinkLocalRules,
		SupportsDefaultDenyPosture: capability.SupportsDefaultDenyPosture,
	}
}

func sanitizeResultModeList(values []ResultMode) []ResultMode {
	if len(values) == 0 {
		return nil
	}
	sanitized := make([]ResultMode, 0, len(values))
	for _, value := range values {
		if current := sanitizeResultMode(value); current != "" {
			sanitized = append(sanitized, current)
		}
	}
	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
}

func resultCapabilityEmpty(capability ResultCapability) bool {
	return !capability.Supported &&
		len(capability.Modes) == 0 &&
		!capability.SupportsDomainRules &&
		!capability.SupportsEndpointRules &&
		!capability.SupportsPrivateRangeRules &&
		!capability.SupportsMetadataEndpoint &&
		!capability.SupportsLoopbackRules &&
		!capability.SupportsLinkLocalRules &&
		!capability.SupportsDefaultDenyPosture
}
