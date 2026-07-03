package networkenforcement

import "encoding/json"

// LifecycleStatus identifies the redaction-safe lifecycle state reported by
// future live network enforcement adapters.
type LifecycleStatus string

const (
	LifecycleStatusRequested   LifecycleStatus = "requested"
	LifecycleStatusPlanned     LifecycleStatus = "planned"
	LifecycleStatusPrepared    LifecycleStatus = "prepared"
	LifecycleStatusStarting    LifecycleStatus = "starting"
	LifecycleStatusApplying    LifecycleStatus = "applying"
	LifecycleStatusActive      LifecycleStatus = "active"
	LifecycleStatusRollingBack LifecycleStatus = "rolling_back"
	LifecycleStatusCleaningUp  LifecycleStatus = "cleaning_up"
	LifecycleStatusStopped     LifecycleStatus = "stopped"
	LifecycleStatusFailed      LifecycleStatus = "failed"
	LifecycleStatusSkipped     LifecycleStatus = "skipped"
)

// LifecycleReasonCode is a sanitized reason label for lifecycle metadata.
type LifecycleReasonCode string

const (
	LifecycleReasonPrepared           LifecycleReasonCode = "prepared"
	LifecycleReasonStarted            LifecycleReasonCode = "started"
	LifecycleReasonApplied            LifecycleReasonCode = "applied"
	LifecycleReasonActive             LifecycleReasonCode = "active"
	LifecycleReasonStopped            LifecycleReasonCode = "stopped"
	LifecycleReasonSkipped            LifecycleReasonCode = "skipped"
	LifecycleReasonAdapterUnsupported LifecycleReasonCode = "adapter_unsupported"
	LifecycleReasonAdapterFailed      LifecycleReasonCode = "adapter_failed"
	LifecycleReasonCapabilityMissing  LifecycleReasonCode = "capability_missing"
	LifecycleReasonCleanupFailed      LifecycleReasonCode = "cleanup_failed"
	LifecycleReasonRollbackFailed     LifecycleReasonCode = "rollback_failed"
	LifecycleReasonActiveCheckFailed  LifecycleReasonCode = "active_check_failed"
)

// LifecycleWarningCode is a sanitized warning label for lifecycle metadata.
type LifecycleWarningCode string

const (
	LifecycleWarningCleanupFailed         LifecycleWarningCode = "cleanup_failed"
	LifecycleWarningRollbackFailed        LifecycleWarningCode = "rollback_failed"
	LifecycleWarningActiveCheckFailed     LifecycleWarningCode = "active_check_failed"
	LifecycleWarningPartialLifecycle      LifecycleWarningCode = "partial_lifecycle"
	LifecycleWarningUnsupportedMechanism  LifecycleWarningCode = "unsupported_mechanism"
	LifecycleWarningSanitizedAdapterError LifecycleWarningCode = "sanitized_adapter_error"
	LifecycleWarningMetadataOnlyFallback  LifecycleWarningCode = "metadata_only_fallback"
)

// LiveLifecycleMetadata is the public redaction-safe live enforcement lifecycle
// contract. It carries only safe IDs, enum-like lifecycle status, policy
// snapshot identity, mechanisms, operations, reason/warning labels, and
// capability labels.
type LiveLifecycleMetadata struct {
	PlanID           string                          `json:"planId,omitempty"`
	AdapterID        string                          `json:"adapterId,omitempty"`
	Status           LifecycleStatus                 `json:"status,omitempty"`
	Mechanisms       []EnforcementMechanism          `json:"mechanisms,omitempty"`
	Operations       []string                        `json:"operations,omitempty"`
	PolicySnapshot   *PolicySnapshotIdentity         `json:"policySnapshot,omitempty"`
	Proxy            *ProxyListenerLifecycleMetadata `json:"proxy,omitempty"`
	Rules            []RuleLifecycleMetadata         `json:"rules,omitempty"`
	CapabilityLabels []string                        `json:"capabilityLabels,omitempty"`
	ReasonCode       LifecycleReasonCode             `json:"reasonCode,omitempty"`
	WarningCodes     []LifecycleWarningCode          `json:"warningCodes,omitempty"`
}

// ProxyListenerLifecycleMetadata records proxy-side lifecycle state without
// exposing listener endpoints, socket paths, process handles, credentials, or
// destination details.
type ProxyListenerLifecycleMetadata struct {
	ID               string                  `json:"id,omitempty"`
	PlanID           string                  `json:"planId,omitempty"`
	AdapterID        string                  `json:"adapterId,omitempty"`
	Status           LifecycleStatus         `json:"status,omitempty"`
	Mechanisms       []EnforcementMechanism  `json:"mechanisms,omitempty"`
	Operations       []string                `json:"operations,omitempty"`
	PolicySnapshot   *PolicySnapshotIdentity `json:"policySnapshot,omitempty"`
	CapabilityLabels []string                `json:"capabilityLabels,omitempty"`
	ReasonCode       LifecycleReasonCode     `json:"reasonCode,omitempty"`
	WarningCodes     []LifecycleWarningCode  `json:"warningCodes,omitempty"`
}

// RuleLifecycleMetadata records firewall/runtime rule lifecycle state without
// exposing rule bodies, command lines, addresses, ports, process handles, or
// credentials.
type RuleLifecycleMetadata struct {
	ID               string                  `json:"id,omitempty"`
	PlanID           string                  `json:"planId,omitempty"`
	AdapterID        string                  `json:"adapterId,omitempty"`
	Status           LifecycleStatus         `json:"status,omitempty"`
	Mechanisms       []EnforcementMechanism  `json:"mechanisms,omitempty"`
	Operations       []string                `json:"operations,omitempty"`
	PolicySnapshot   *PolicySnapshotIdentity `json:"policySnapshot,omitempty"`
	CapabilityLabels []string                `json:"capabilityLabels,omitempty"`
	ReasonCode       LifecycleReasonCode     `json:"reasonCode,omitempty"`
	WarningCodes     []LifecycleWarningCode  `json:"warningCodes,omitempty"`
}

// SanitizeLiveLifecycleMetadata returns a redaction-safe lifecycle metadata
// copy. Unsafe dynamic identifiers and labels are cleared so omitempty removes
// them from durable JSON.
func SanitizeLiveLifecycleMetadata(metadata LiveLifecycleMetadata) LiveLifecycleMetadata {
	return LiveLifecycleMetadata{
		PlanID:           sanitizeIdentifier(metadata.PlanID),
		AdapterID:        sanitizeIdentifier(metadata.AdapterID),
		Status:           sanitizeLifecycleStatus(metadata.Status),
		Mechanisms:       sanitizeEnforcementMechanismList(metadata.Mechanisms),
		Operations:       sanitizeIdentifierList(metadata.Operations),
		PolicySnapshot:   sanitizePolicySnapshotIdentityPtr(metadata.PolicySnapshot),
		Proxy:            sanitizeProxyListenerLifecycleMetadataPtr(metadata.Proxy),
		Rules:            sanitizeRuleLifecycleMetadataList(metadata.Rules),
		CapabilityLabels: sanitizeIdentifierList(metadata.CapabilityLabels),
		ReasonCode:       sanitizeLifecycleReasonCode(metadata.ReasonCode),
		WarningCodes:     sanitizeLifecycleWarningCodeList(metadata.WarningCodes),
	}
}

func SanitizeProxyListenerLifecycleMetadata(metadata ProxyListenerLifecycleMetadata) ProxyListenerLifecycleMetadata {
	return ProxyListenerLifecycleMetadata{
		ID:               sanitizeIdentifier(metadata.ID),
		PlanID:           sanitizeIdentifier(metadata.PlanID),
		AdapterID:        sanitizeIdentifier(metadata.AdapterID),
		Status:           sanitizeLifecycleStatus(metadata.Status),
		Mechanisms:       sanitizeEnforcementMechanismList(metadata.Mechanisms),
		Operations:       sanitizeIdentifierList(metadata.Operations),
		PolicySnapshot:   sanitizePolicySnapshotIdentityPtr(metadata.PolicySnapshot),
		CapabilityLabels: sanitizeIdentifierList(metadata.CapabilityLabels),
		ReasonCode:       sanitizeLifecycleReasonCode(metadata.ReasonCode),
		WarningCodes:     sanitizeLifecycleWarningCodeList(metadata.WarningCodes),
	}
}

func SanitizeRuleLifecycleMetadata(metadata RuleLifecycleMetadata) RuleLifecycleMetadata {
	return RuleLifecycleMetadata{
		ID:               sanitizeIdentifier(metadata.ID),
		PlanID:           sanitizeIdentifier(metadata.PlanID),
		AdapterID:        sanitizeIdentifier(metadata.AdapterID),
		Status:           sanitizeLifecycleStatus(metadata.Status),
		Mechanisms:       sanitizeEnforcementMechanismList(metadata.Mechanisms),
		Operations:       sanitizeIdentifierList(metadata.Operations),
		PolicySnapshot:   sanitizePolicySnapshotIdentityPtr(metadata.PolicySnapshot),
		CapabilityLabels: sanitizeIdentifierList(metadata.CapabilityLabels),
		ReasonCode:       sanitizeLifecycleReasonCode(metadata.ReasonCode),
		WarningCodes:     sanitizeLifecycleWarningCodeList(metadata.WarningCodes),
	}
}

func (m LiveLifecycleMetadata) MarshalJSON() ([]byte, error) {
	type liveLifecycleMetadataJSON LiveLifecycleMetadata
	sanitized := SanitizeLiveLifecycleMetadata(m)
	return json.Marshal(liveLifecycleMetadataJSON(sanitized))
}

func (m ProxyListenerLifecycleMetadata) MarshalJSON() ([]byte, error) {
	type proxyListenerLifecycleMetadataJSON ProxyListenerLifecycleMetadata
	sanitized := SanitizeProxyListenerLifecycleMetadata(m)
	return json.Marshal(proxyListenerLifecycleMetadataJSON(sanitized))
}

func (m RuleLifecycleMetadata) MarshalJSON() ([]byte, error) {
	type ruleLifecycleMetadataJSON RuleLifecycleMetadata
	sanitized := SanitizeRuleLifecycleMetadata(m)
	return json.Marshal(ruleLifecycleMetadataJSON(sanitized))
}

func sanitizeProxyListenerLifecycleMetadataPtr(metadata *ProxyListenerLifecycleMetadata) *ProxyListenerLifecycleMetadata {
	if metadata == nil {
		return nil
	}
	sanitized := SanitizeProxyListenerLifecycleMetadata(*metadata)
	if proxyListenerLifecycleMetadataEmpty(sanitized) {
		return nil
	}
	return &sanitized
}

func sanitizeRuleLifecycleMetadataList(values []RuleLifecycleMetadata) []RuleLifecycleMetadata {
	if len(values) == 0 {
		return nil
	}
	sanitized := make([]RuleLifecycleMetadata, 0, len(values))
	for _, value := range values {
		current := SanitizeRuleLifecycleMetadata(value)
		if !ruleLifecycleMetadataEmpty(current) {
			sanitized = append(sanitized, current)
		}
	}
	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
}

func proxyListenerLifecycleMetadataEmpty(metadata ProxyListenerLifecycleMetadata) bool {
	return metadata.ID == "" &&
		metadata.PlanID == "" &&
		metadata.AdapterID == "" &&
		metadata.Status == "" &&
		len(metadata.Mechanisms) == 0 &&
		len(metadata.Operations) == 0 &&
		metadata.PolicySnapshot == nil &&
		len(metadata.CapabilityLabels) == 0 &&
		metadata.ReasonCode == "" &&
		len(metadata.WarningCodes) == 0
}

func ruleLifecycleMetadataEmpty(metadata RuleLifecycleMetadata) bool {
	return metadata.ID == "" &&
		metadata.PlanID == "" &&
		metadata.AdapterID == "" &&
		metadata.Status == "" &&
		len(metadata.Mechanisms) == 0 &&
		len(metadata.Operations) == 0 &&
		metadata.PolicySnapshot == nil &&
		len(metadata.CapabilityLabels) == 0 &&
		metadata.ReasonCode == "" &&
		len(metadata.WarningCodes) == 0
}

func sanitizeLifecycleStatus(value LifecycleStatus) LifecycleStatus {
	normalized := LifecycleStatus(normalizeEnum(string(value)))
	switch normalized {
	case LifecycleStatusRequested,
		LifecycleStatusPlanned,
		LifecycleStatusPrepared,
		LifecycleStatusStarting,
		LifecycleStatusApplying,
		LifecycleStatusActive,
		LifecycleStatusRollingBack,
		LifecycleStatusCleaningUp,
		LifecycleStatusStopped,
		LifecycleStatusFailed,
		LifecycleStatusSkipped:
		return normalized
	default:
		return ""
	}
}

func sanitizeLifecycleReasonCode(value LifecycleReasonCode) LifecycleReasonCode {
	normalized := LifecycleReasonCode(normalizeEnum(string(value)))
	switch normalized {
	case LifecycleReasonPrepared,
		LifecycleReasonStarted,
		LifecycleReasonApplied,
		LifecycleReasonActive,
		LifecycleReasonStopped,
		LifecycleReasonSkipped,
		LifecycleReasonAdapterUnsupported,
		LifecycleReasonAdapterFailed,
		LifecycleReasonCapabilityMissing,
		LifecycleReasonCleanupFailed,
		LifecycleReasonRollbackFailed,
		LifecycleReasonActiveCheckFailed:
		return normalized
	default:
		return ""
	}
}

func sanitizeLifecycleWarningCode(value LifecycleWarningCode) LifecycleWarningCode {
	normalized := LifecycleWarningCode(normalizeEnum(string(value)))
	switch normalized {
	case LifecycleWarningCleanupFailed,
		LifecycleWarningRollbackFailed,
		LifecycleWarningActiveCheckFailed,
		LifecycleWarningPartialLifecycle,
		LifecycleWarningUnsupportedMechanism,
		LifecycleWarningSanitizedAdapterError,
		LifecycleWarningMetadataOnlyFallback:
		return normalized
	default:
		return ""
	}
}

func sanitizeLifecycleWarningCodeList(values []LifecycleWarningCode) []LifecycleWarningCode {
	if len(values) == 0 {
		return nil
	}
	sanitized := make([]LifecycleWarningCode, 0, len(values))
	for _, value := range values {
		if current := sanitizeLifecycleWarningCode(value); current != "" {
			sanitized = append(sanitized, current)
		}
	}
	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
}
