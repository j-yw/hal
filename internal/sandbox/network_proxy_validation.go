package sandbox

import "strings"

// SandboxNetworkProxyValidationCode identifies a sanitized proxy metadata
// validation failure. Codes must not include raw request, destination, or
// credential values.
type SandboxNetworkProxyValidationCode string

const (
	SandboxNetworkProxyValidationMissingRequiredField SandboxNetworkProxyValidationCode = "missing_required_field"
	SandboxNetworkProxyValidationInvalidSource        SandboxNetworkProxyValidationCode = "invalid_source"
	SandboxNetworkProxyValidationInvalidPolicyPreset  SandboxNetworkProxyValidationCode = "invalid_policy_preset"
	SandboxNetworkProxyValidationInvalidEnforcement   SandboxNetworkProxyValidationCode = "invalid_enforcement_mode"
	SandboxNetworkProxyValidationUnsafeMetadata       SandboxNetworkProxyValidationCode = "unsafe_metadata"
)

// SandboxNetworkProxyValidationError identifies invalid proxy metadata by safe
// field name only. It intentionally omits rejected input values.
type SandboxNetworkProxyValidationError struct {
	Code    SandboxNetworkProxyValidationCode `json:"code"`
	Field   string                            `json:"field,omitempty"`
	Message string                            `json:"message,omitempty"`
}

// SandboxNetworkProxyValidationResult is the deterministic output of pure
// proxy-session metadata validation and normalization.
type SandboxNetworkProxyValidationResult struct {
	Valid      bool                                 `json:"valid"`
	Normalized *SandboxNetworkProxySessionMetadata  `json:"normalized,omitempty"`
	Errors     []SandboxNetworkProxyValidationError `json:"errors,omitempty"`
}

// SandboxNetworkPolicyDecisionLogValidationCode identifies a sanitized policy
// decision-log validation failure. Codes must not include raw destinations,
// request values, endpoints, credentials, or query data.
type SandboxNetworkPolicyDecisionLogValidationCode string

const (
	SandboxNetworkPolicyDecisionLogValidationMissingRequiredField    SandboxNetworkPolicyDecisionLogValidationCode = "missing_required_field"
	SandboxNetworkPolicyDecisionLogValidationInvalidSource           SandboxNetworkPolicyDecisionLogValidationCode = "invalid_source"
	SandboxNetworkPolicyDecisionLogValidationInvalidOutcome          SandboxNetworkPolicyDecisionLogValidationCode = "invalid_outcome"
	SandboxNetworkPolicyDecisionLogValidationInvalidReasonCode       SandboxNetworkPolicyDecisionLogValidationCode = "invalid_reason_code"
	SandboxNetworkPolicyDecisionLogValidationInvalidDestination      SandboxNetworkPolicyDecisionLogValidationCode = "invalid_destination_category"
	SandboxNetworkPolicyDecisionLogValidationInvalidRuleKind         SandboxNetworkPolicyDecisionLogValidationCode = "invalid_rule_kind"
	SandboxNetworkPolicyDecisionLogValidationInvalidPolicyPreset     SandboxNetworkPolicyDecisionLogValidationCode = "invalid_policy_preset"
	SandboxNetworkPolicyDecisionLogValidationInvalidEnforcement      SandboxNetworkPolicyDecisionLogValidationCode = "invalid_enforcement_mode"
	SandboxNetworkPolicyDecisionLogValidationUnsafeRequestMetadata   SandboxNetworkPolicyDecisionLogValidationCode = "unsafe_request_metadata"
	SandboxNetworkPolicyDecisionLogValidationUnsafeMetadata          SandboxNetworkPolicyDecisionLogValidationCode = "unsafe_metadata"
	SandboxNetworkPolicyDecisionLogValidationInvalidEnforcementClaim SandboxNetworkPolicyDecisionLogValidationCode = "invalid_enforcement_claim"
)

// SandboxNetworkPolicyDecisionLogValidationError identifies invalid durable
// decision-log metadata by safe record index and field name only.
type SandboxNetworkPolicyDecisionLogValidationError struct {
	Code        SandboxNetworkPolicyDecisionLogValidationCode `json:"code"`
	RecordIndex int                                           `json:"recordIndex"`
	Field       string                                        `json:"field,omitempty"`
	Message     string                                        `json:"message,omitempty"`
}

// SandboxNetworkPolicyDecisionLogValidationResult is the deterministic output
// of pure policy decision-log validation and normalization.
type SandboxNetworkPolicyDecisionLogValidationResult struct {
	Valid      bool                                             `json:"valid"`
	Normalized []SandboxNetworkPolicyDecisionLogRecord          `json:"normalized,omitempty"`
	Errors     []SandboxNetworkPolicyDecisionLogValidationError `json:"errors,omitempty"`
}

// ValidateAndNormalizeSandboxNetworkProxySessionMetadata validates durable
// proxy-session metadata without inspecting hosts, starting listeners, or
// inferring runtime enforcement capability.
func ValidateAndNormalizeSandboxNetworkProxySessionMetadata(session SandboxNetworkProxySessionMetadata) SandboxNetworkProxyValidationResult {
	normalized := normalizeSandboxNetworkProxySessionMetadata(session)
	result := SandboxNetworkProxyValidationResult{Valid: true}

	if normalized.ID == "" {
		result.addError("id", SandboxNetworkProxyValidationMissingRequiredField, "proxy session id is required")
	} else if unsafeSandboxNetworkProxyIdentifierMetadata(normalized.ID) {
		result.addError("id", SandboxNetworkProxyValidationUnsafeMetadata, "proxy session id must be a safe identifier")
	}
	if normalized.Source == "" {
		result.addError("source", SandboxNetworkProxyValidationMissingRequiredField, "proxy session source is required")
	} else if !validSandboxNetworkPolicyDecisionSource(normalized.Source) {
		result.addError("source", SandboxNetworkProxyValidationInvalidSource, "proxy session source is unsupported")
	}
	if normalized.PolicySnapshot != nil {
		if normalized.PolicySnapshot.ID == "" {
			result.addError("policySnapshot.id", SandboxNetworkProxyValidationMissingRequiredField, "policy snapshot id is required")
		} else if unsafeSandboxNetworkProxyIdentifierMetadata(normalized.PolicySnapshot.ID) {
			result.addError("policySnapshot.id", SandboxNetworkProxyValidationUnsafeMetadata, "policy snapshot id must be a safe identifier")
		}
		if unsafeSandboxNetworkProxyIdentifierMetadata(normalized.PolicySnapshot.Version) {
			result.addError("policySnapshot.version", SandboxNetworkProxyValidationUnsafeMetadata, "policy snapshot version must be a safe identifier")
		}
		if unsafeSandboxNetworkProxyIdentifierMetadata(normalized.PolicySnapshot.RuleSetID) {
			result.addError("policySnapshot.ruleSetId", SandboxNetworkProxyValidationUnsafeMetadata, "policy snapshot rule set id must be a safe identifier")
		}
		if normalized.PolicySnapshot.Preset != "" && !validSandboxNetworkPolicyPreset(normalized.PolicySnapshot.Preset) {
			result.addError("policySnapshot.preset", SandboxNetworkProxyValidationInvalidPolicyPreset, "policy snapshot preset is unsupported")
		}
	}
	if normalized.EnforcementMode != "" && !validSandboxNetworkProxyEnforcementMode(normalized.EnforcementMode) {
		result.addError("enforcementMode", SandboxNetworkProxyValidationInvalidEnforcement, "proxy enforcement mode is unsupported")
	}

	if len(result.Errors) > 0 {
		result.Valid = false
		return result
	}
	result.Normalized = &normalized
	return result
}

// ValidateAndNormalizeSandboxNetworkPolicyDecisionLogRecord validates a single
// durable policy decision-log record through the same pure metadata path used
// for decision-log batches.
func ValidateAndNormalizeSandboxNetworkPolicyDecisionLogRecord(record SandboxNetworkPolicyDecisionLogRecord) SandboxNetworkPolicyDecisionLogValidationResult {
	return ValidateAndNormalizeSandboxNetworkPolicyDecisionLogRecords([]SandboxNetworkPolicyDecisionLogRecord{record})
}

// ValidateAndNormalizeSandboxNetworkPolicyDecisionLogRecords validates durable
// policy decision logs without inspecting hosts, starting listeners, opening
// sockets, or inferring runtime enforcement capability.
func ValidateAndNormalizeSandboxNetworkPolicyDecisionLogRecords(records []SandboxNetworkPolicyDecisionLogRecord) SandboxNetworkPolicyDecisionLogValidationResult {
	result := SandboxNetworkPolicyDecisionLogValidationResult{Valid: true}
	normalized := make([]SandboxNetworkPolicyDecisionLogRecord, 0, len(records))

	for i, record := range records {
		current := normalizeSandboxNetworkPolicyDecisionLogRecord(record)
		validateSandboxNetworkPolicyDecisionLogRecord(&result, i, current)
		normalized = append(normalized, current)
	}

	if len(result.Errors) > 0 {
		result.Valid = false
		return result
	}
	result.Normalized = normalized
	return result
}

// SanitizeSandboxNetworkProxySessionMetadata returns a normalized copy of
// proxy-session metadata safe for durable manifests and records. Unsafe dynamic
// identifiers are cleared instead of redacted so optional JSON fields disappear.
func SanitizeSandboxNetworkProxySessionMetadata(session SandboxNetworkProxySessionMetadata) SandboxNetworkProxySessionMetadata {
	sanitized := normalizeSandboxNetworkProxySessionMetadata(session)
	sanitized.ID = sanitizeSandboxNetworkProxyIdentifier(sanitized.ID)
	sanitized.Source = sanitizeSandboxNetworkPolicyDecisionSourceValue(sanitized.Source)
	sanitized.EnforcementMode = sanitizeSandboxNetworkProxyEnforcementModeValue(sanitized.EnforcementMode)
	sanitized.PolicySnapshot = sanitizeSandboxNetworkPolicySnapshotIdentityPtr(sanitized.PolicySnapshot)
	return sanitized
}

// SanitizeSandboxNetworkEnforcementProofMetadata returns a normalized safe
// copy of active-enforcement proof labels. Unsafe IDs or unsupported status
// labels are cleared so callers can fail closed.
func SanitizeSandboxNetworkEnforcementProofMetadata(proof SandboxNetworkEnforcementProofMetadata) SandboxNetworkEnforcementProofMetadata {
	sanitized := normalizeSandboxNetworkEnforcementProofMetadata(proof)
	sanitized.NetworkProxySessionID = sanitizeSandboxNetworkProxyIdentifier(sanitized.NetworkProxySessionID)
	sanitized.PolicySnapshotID = sanitizeSandboxNetworkProxyIdentifier(sanitized.PolicySnapshotID)
	sanitized.NetworkEnforcementPlanID = sanitizeSandboxNetworkProxyIdentifier(sanitized.NetworkEnforcementPlanID)
	sanitized.ProxyLifecycleStatus = sanitizeSandboxNetworkEnforcementLifecycleStatus(sanitized.ProxyLifecycleStatus)
	sanitized.ProxyLifecycleReasonCode = sanitizeSandboxNetworkEnforcementLifecycleReasonCode(sanitized.ProxyLifecycleReasonCode)
	sanitized.FirewallLifecycleStatus = sanitizeSandboxNetworkEnforcementLifecycleStatus(sanitized.FirewallLifecycleStatus)
	sanitized.FirewallLifecycleReasonCode = sanitizeSandboxNetworkEnforcementLifecycleReasonCode(sanitized.FirewallLifecycleReasonCode)
	sanitized.ResultOutcome = sanitizeSandboxNetworkEnforcementResultOutcome(sanitized.ResultOutcome)
	sanitized.ResultEnforcementMode = sanitizeSandboxNetworkProxyEnforcementModeValue(sanitized.ResultEnforcementMode)
	sanitized.WarningCount = sanitizeSandboxNetworkEnforcementWarningCount(sanitized.WarningCount)
	return sanitized
}

// SandboxNetworkEnforcementProofProvesActiveHTTPProxy returns true only for
// sanitized proof metadata that shows an active proxy lifecycle and a
// successful supported proxy-capable enforcement result.
func SandboxNetworkEnforcementProofProvesActiveHTTPProxy(proof SandboxNetworkEnforcementProofMetadata) bool {
	sanitized := SanitizeSandboxNetworkEnforcementProofMetadata(proof)
	if !sandboxNetworkEnforcementProofHasRequiredIDs(sanitized) {
		return false
	}
	if !sandboxNetworkEnforcementProofHasActiveProxy(sanitized) ||
		sanitized.ResultOutcome != "success" ||
		!sanitized.ResultSupported ||
		sanitized.WarningCount > 0 {
		return false
	}
	switch sanitized.ResultEnforcementMode {
	case SandboxNetworkEnforcementModeProxy, SandboxNetworkEnforcementModeProxyFirewall:
		return true
	default:
		return false
	}
}

// SandboxNetworkEnforcementProofProvesActiveProxyFirewall returns true only
// when sanitized proof metadata shows both proxy and firewall lifecycles active
// and the result explicitly supports proxy_firewall enforcement.
func SandboxNetworkEnforcementProofProvesActiveProxyFirewall(proof SandboxNetworkEnforcementProofMetadata) bool {
	sanitized := SanitizeSandboxNetworkEnforcementProofMetadata(proof)
	return sandboxNetworkEnforcementProofHasRequiredIDs(sanitized) &&
		sandboxNetworkEnforcementProofHasActiveProxy(sanitized) &&
		sandboxNetworkEnforcementProofHasActiveFirewall(sanitized) &&
		sanitized.ResultOutcome == "success" &&
		sanitized.ResultEnforcementMode == SandboxNetworkEnforcementModeProxyFirewall &&
		sanitized.ResultSupported &&
		sanitized.WarningCount == 0
}

func sandboxNetworkEnforcementProofEmpty(proof SandboxNetworkEnforcementProofMetadata) bool {
	return proof.NetworkProxySessionID == "" &&
		proof.PolicySnapshotID == "" &&
		proof.NetworkEnforcementPlanID == "" &&
		proof.ProxyLifecycleStatus == "" &&
		proof.ProxyLifecycleReasonCode == "" &&
		proof.FirewallLifecycleStatus == "" &&
		proof.FirewallLifecycleReasonCode == "" &&
		proof.ResultOutcome == "" &&
		proof.ResultEnforcementMode == "" &&
		!proof.ResultSupported &&
		proof.WarningCount == 0
}

func sandboxNetworkEnforcementProofHasRequiredIDs(proof SandboxNetworkEnforcementProofMetadata) bool {
	return proof.NetworkProxySessionID != "" &&
		proof.PolicySnapshotID != "" &&
		proof.NetworkEnforcementPlanID != ""
}

func sandboxNetworkEnforcementProofHasActiveProxy(proof SandboxNetworkEnforcementProofMetadata) bool {
	return proof.ProxyLifecycleStatus == "active" &&
		proof.ProxyLifecycleReasonCode == "active"
}

func sandboxNetworkEnforcementProofHasActiveFirewall(proof SandboxNetworkEnforcementProofMetadata) bool {
	return proof.FirewallLifecycleStatus == "active" &&
		proof.FirewallLifecycleReasonCode == "active"
}

// SanitizeSandboxNetworkPolicyDecisionLogRecord returns a normalized copy of a
// policy decision-log record safe for durable manifests and records.
func SanitizeSandboxNetworkPolicyDecisionLogRecord(record SandboxNetworkPolicyDecisionLogRecord) SandboxNetworkPolicyDecisionLogRecord {
	sanitized := normalizeSandboxNetworkPolicyDecisionLogRecord(record)
	sanitized.ID = sanitizeSandboxNetworkProxyIdentifier(sanitized.ID)
	sanitized.Source = sanitizeSandboxNetworkPolicyDecisionSourceValue(sanitized.Source)
	sanitized.ProxySessionID = sanitizeSandboxNetworkProxyIdentifier(sanitized.ProxySessionID)
	sanitized.PolicySnapshot = sanitizeSandboxNetworkPolicySnapshotIdentityPtr(sanitized.PolicySnapshot)
	sanitized.Request = sanitizeSandboxNetworkPolicyRequestSummaryPtr(sanitized.Request)
	sanitized.Outcome = sanitizeSandboxNetworkPolicyDecisionOutcomeValue(sanitized.Outcome)
	sanitized.ReasonCode = sanitizeSandboxNetworkPolicyDecisionReasonCodeValue(sanitized.ReasonCode)
	sanitized.RuleKind = sanitizeSandboxNetworkPolicyRuleKindValue(sanitized.RuleKind)
	sanitized.PolicyPreset = sanitizeSandboxNetworkPolicyPresetValue(sanitized.PolicyPreset)
	sanitized.EnforcementMode = sanitizeSandboxNetworkProxyEnforcementModeValue(sanitized.EnforcementMode)
	if sanitized.Enforced != nil &&
		*sanitized.Enforced &&
		!sandboxNetworkPolicyModeCanEnforce(sanitized.EnforcementMode) {
		sanitized.Enforced = nil
	}
	return sanitized
}

// SanitizeSandboxNetworkPolicyDecisionLogRecords returns a sanitized copy of a
// decision-log batch.
func SanitizeSandboxNetworkPolicyDecisionLogRecords(records []SandboxNetworkPolicyDecisionLogRecord) []SandboxNetworkPolicyDecisionLogRecord {
	if len(records) == 0 {
		return nil
	}
	sanitized := make([]SandboxNetworkPolicyDecisionLogRecord, 0, len(records))
	for _, record := range records {
		sanitized = append(sanitized, SanitizeSandboxNetworkPolicyDecisionLogRecord(record))
	}
	return sanitized
}

func normalizeSandboxNetworkProxySessionMetadata(session SandboxNetworkProxySessionMetadata) SandboxNetworkProxySessionMetadata {
	normalized := SandboxNetworkProxySessionMetadata{
		ID:              strings.TrimSpace(session.ID),
		Source:          normalizeSandboxNetworkPolicyDecisionSource(session.Source),
		EnforcementMode: normalizeSandboxNetworkProxyEnforcementMode(session.EnforcementMode),
	}
	if session.PolicySnapshot != nil {
		normalized.PolicySnapshot = &SandboxNetworkPolicySnapshotIdentity{
			ID:        strings.TrimSpace(session.PolicySnapshot.ID),
			Version:   strings.TrimSpace(session.PolicySnapshot.Version),
			Preset:    normalizeSandboxNetworkPolicyPreset(session.PolicySnapshot.Preset),
			RuleSetID: strings.TrimSpace(session.PolicySnapshot.RuleSetID),
		}
	}
	return normalized
}

func normalizeSandboxNetworkEnforcementProofMetadata(proof SandboxNetworkEnforcementProofMetadata) SandboxNetworkEnforcementProofMetadata {
	return SandboxNetworkEnforcementProofMetadata{
		NetworkProxySessionID:       strings.TrimSpace(proof.NetworkProxySessionID),
		PolicySnapshotID:            strings.TrimSpace(proof.PolicySnapshotID),
		NetworkEnforcementPlanID:    strings.TrimSpace(proof.NetworkEnforcementPlanID),
		ProxyLifecycleStatus:        strings.ToLower(strings.TrimSpace(proof.ProxyLifecycleStatus)),
		ProxyLifecycleReasonCode:    strings.ToLower(strings.TrimSpace(proof.ProxyLifecycleReasonCode)),
		FirewallLifecycleStatus:     strings.ToLower(strings.TrimSpace(proof.FirewallLifecycleStatus)),
		FirewallLifecycleReasonCode: strings.ToLower(strings.TrimSpace(proof.FirewallLifecycleReasonCode)),
		ResultOutcome:               strings.ToLower(strings.TrimSpace(proof.ResultOutcome)),
		ResultEnforcementMode:       normalizeSandboxNetworkProxyEnforcementMode(proof.ResultEnforcementMode),
		ResultSupported:             proof.ResultSupported,
		WarningCount:                proof.WarningCount,
	}
}

func normalizeSandboxNetworkPolicyDecisionLogRecord(record SandboxNetworkPolicyDecisionLogRecord) SandboxNetworkPolicyDecisionLogRecord {
	normalized := SandboxNetworkPolicyDecisionLogRecord{
		ID:              strings.TrimSpace(record.ID),
		Source:          normalizeSandboxNetworkPolicyDecisionSource(record.Source),
		ProxySessionID:  strings.TrimSpace(record.ProxySessionID),
		Outcome:         normalizeSandboxNetworkPolicyDecisionOutcome(record.Outcome),
		ReasonCode:      normalizeSandboxNetworkPolicyDecisionReasonCode(record.ReasonCode),
		RuleKind:        normalizeSandboxNetworkPolicyRuleKind(record.RuleKind),
		PolicyPreset:    normalizeSandboxNetworkPolicyPreset(record.PolicyPreset),
		EnforcementMode: normalizeSandboxNetworkProxyEnforcementMode(record.EnforcementMode),
	}
	if record.PolicySnapshot != nil {
		normalized.PolicySnapshot = &SandboxNetworkPolicySnapshotIdentity{
			ID:        strings.TrimSpace(record.PolicySnapshot.ID),
			Version:   strings.TrimSpace(record.PolicySnapshot.Version),
			Preset:    normalizeSandboxNetworkPolicyPreset(record.PolicySnapshot.Preset),
			RuleSetID: strings.TrimSpace(record.PolicySnapshot.RuleSetID),
		}
	}
	if record.Request != nil {
		normalized.Request = &SandboxNetworkPolicyRequestSummary{
			ID:                  strings.TrimSpace(record.Request.ID),
			Operation:           strings.TrimSpace(record.Request.Operation),
			DestinationCategory: normalizeSandboxNetworkPolicyDestinationCategory(record.Request.DestinationCategory),
		}
	}
	if record.Enforced != nil {
		enforced := *record.Enforced
		normalized.Enforced = &enforced
	}
	return normalized
}

func sanitizeSandboxNetworkPolicySnapshotIdentityPtr(snapshot *SandboxNetworkPolicySnapshotIdentity) *SandboxNetworkPolicySnapshotIdentity {
	if snapshot == nil {
		return nil
	}
	sanitized := SandboxNetworkPolicySnapshotIdentity{
		ID:        sanitizeSandboxNetworkProxyIdentifier(snapshot.ID),
		Version:   sanitizeSandboxNetworkProxyIdentifier(snapshot.Version),
		Preset:    sanitizeSandboxNetworkPolicyPresetValue(snapshot.Preset),
		RuleSetID: sanitizeSandboxNetworkProxyIdentifier(snapshot.RuleSetID),
	}
	if sanitized.ID == "" {
		return nil
	}
	return &sanitized
}

func sanitizeSandboxNetworkPolicyRequestSummaryPtr(request *SandboxNetworkPolicyRequestSummary) *SandboxNetworkPolicyRequestSummary {
	if request == nil {
		return nil
	}
	sanitized := SandboxNetworkPolicyRequestSummary{
		ID:                  sanitizeSandboxNetworkProxyIdentifier(request.ID),
		Operation:           sanitizeSandboxNetworkProxyLabel(request.Operation),
		DestinationCategory: sanitizeSandboxNetworkPolicyDestinationCategoryValue(request.DestinationCategory),
	}
	if sanitized.ID == "" && sanitized.Operation == "" && sanitized.DestinationCategory == "" {
		return nil
	}
	return &sanitized
}

func sanitizeSandboxNetworkPolicyDecisionSourceValue(source SandboxNetworkPolicyDecisionSource) SandboxNetworkPolicyDecisionSource {
	source = normalizeSandboxNetworkPolicyDecisionSource(source)
	if !validSandboxNetworkPolicyDecisionSource(source) {
		return ""
	}
	return source
}

func sanitizeSandboxNetworkPolicyDecisionOutcomeValue(outcome SandboxNetworkPolicyDecisionOutcome) SandboxNetworkPolicyDecisionOutcome {
	outcome = normalizeSandboxNetworkPolicyDecisionOutcome(outcome)
	if !validSandboxNetworkPolicyDecisionOutcome(outcome) {
		return ""
	}
	return outcome
}

func sanitizeSandboxNetworkPolicyDecisionReasonCodeValue(reason SandboxNetworkPolicyDecisionReasonCode) SandboxNetworkPolicyDecisionReasonCode {
	reason = normalizeSandboxNetworkPolicyDecisionReasonCode(reason)
	if reason != "" && !validSandboxNetworkPolicyDecisionReasonCode(reason) {
		return ""
	}
	return reason
}

func sanitizeSandboxNetworkPolicyDestinationCategoryValue(category SandboxNetworkPolicyDestinationCategory) SandboxNetworkPolicyDestinationCategory {
	category = normalizeSandboxNetworkPolicyDestinationCategory(category)
	if category != "" && !validSandboxNetworkPolicyDestinationCategory(category) {
		return ""
	}
	return category
}

func sanitizeSandboxNetworkPolicyRuleKindValue(kind SandboxNetworkPolicyRuleKind) SandboxNetworkPolicyRuleKind {
	kind = normalizeSandboxNetworkPolicyRuleKind(kind)
	if kind != "" && !validSandboxNetworkPolicyRuleKind(kind) {
		return ""
	}
	return kind
}

func sanitizeSandboxNetworkPolicyPresetValue(preset SandboxNetworkPolicyPreset) SandboxNetworkPolicyPreset {
	preset = normalizeSandboxNetworkPolicyPreset(preset)
	if preset != "" && !validSandboxNetworkPolicyPreset(preset) {
		return ""
	}
	return preset
}

func sanitizeSandboxNetworkProxyEnforcementModeValue(mode string) string {
	mode = normalizeSandboxNetworkProxyEnforcementMode(mode)
	if mode != "" && !validSandboxNetworkProxyEnforcementMode(mode) {
		return ""
	}
	return mode
}

func sanitizeSandboxNetworkEnforcementLifecycleStatus(status string) string {
	status = strings.ToLower(strings.TrimSpace(status))
	switch status {
	case "requested", "planned", "prepared", "starting", "applying", "active", "rolling_back", "cleaning_up", "stopped", "failed", "skipped":
		return status
	default:
		return ""
	}
}

func sanitizeSandboxNetworkEnforcementLifecycleReasonCode(reason string) string {
	reason = strings.ToLower(strings.TrimSpace(reason))
	switch reason {
	case "prepared", "started", "applied", "active", "stopped", "skipped", "adapter_unsupported", "adapter_failed", "capability_missing", "cleanup_failed", "rollback_failed", "active_check_failed":
		return reason
	default:
		return ""
	}
}

func sanitizeSandboxNetworkEnforcementResultOutcome(outcome string) string {
	outcome = strings.ToLower(strings.TrimSpace(outcome))
	switch outcome {
	case "success", "best_effort", "unsupported", "failure":
		return outcome
	default:
		return ""
	}
}

func sanitizeSandboxNetworkEnforcementWarningCount(count int) int {
	if count < 0 {
		return 0
	}
	if count > 1000 {
		return 1000
	}
	return count
}

func sanitizeSandboxNetworkProxyLabel(value string) string {
	return sanitizeSandboxNetworkProxyIdentifier(value)
}

func sanitizeSandboxNetworkProxyIdentifier(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || unsafeSandboxNetworkProxyFreeformMetadata(value) {
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

func unsafeSandboxNetworkProxyFreeformMetadata(value string) bool {
	if sandboxNetworkProxyAllDigits(value) {
		return true
	}
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"://",
		"@",
		"authorization",
		"bearer",
		"token",
		"secret",
		"credential",
		"password",
		"api_key",
		"apikey",
		"access_key",
		"private_key",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	if strings.Contains(value, ".") || strings.ContainsAny(value, "/\\?#\r\n\t \"'`{}[]()<>|;&=$:") {
		return true
	}
	return false
}

func sandboxNetworkProxyAllDigits(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return value != ""
}

func normalizeSandboxNetworkPolicyDecisionSource(source SandboxNetworkPolicyDecisionSource) SandboxNetworkPolicyDecisionSource {
	return SandboxNetworkPolicyDecisionSource(strings.ToLower(strings.TrimSpace(string(source))))
}

func normalizeSandboxNetworkPolicyDecisionOutcome(outcome SandboxNetworkPolicyDecisionOutcome) SandboxNetworkPolicyDecisionOutcome {
	return SandboxNetworkPolicyDecisionOutcome(strings.ToLower(strings.TrimSpace(string(outcome))))
}

func normalizeSandboxNetworkPolicyDecisionReasonCode(reason SandboxNetworkPolicyDecisionReasonCode) SandboxNetworkPolicyDecisionReasonCode {
	return SandboxNetworkPolicyDecisionReasonCode(strings.ToLower(strings.TrimSpace(string(reason))))
}

func normalizeSandboxNetworkPolicyDestinationCategory(category SandboxNetworkPolicyDestinationCategory) SandboxNetworkPolicyDestinationCategory {
	return SandboxNetworkPolicyDestinationCategory(strings.ToLower(strings.TrimSpace(string(category))))
}

func normalizeSandboxNetworkPolicyRuleKind(kind SandboxNetworkPolicyRuleKind) SandboxNetworkPolicyRuleKind {
	return SandboxNetworkPolicyRuleKind(strings.ToLower(strings.TrimSpace(string(kind))))
}

func normalizeSandboxNetworkPolicyPreset(preset SandboxNetworkPolicyPreset) SandboxNetworkPolicyPreset {
	return SandboxNetworkPolicyPreset(strings.ToLower(strings.TrimSpace(string(preset))))
}

func normalizeSandboxNetworkProxyEnforcementMode(mode string) string {
	return strings.ToLower(strings.TrimSpace(mode))
}

func validateSandboxNetworkPolicyDecisionLogRecord(result *SandboxNetworkPolicyDecisionLogValidationResult, index int, record SandboxNetworkPolicyDecisionLogRecord) {
	if record.Source == "" {
		result.addError(index, "source", SandboxNetworkPolicyDecisionLogValidationMissingRequiredField, "decision log source is required")
	} else if !validSandboxNetworkPolicyDecisionSource(record.Source) {
		result.addError(index, "source", SandboxNetworkPolicyDecisionLogValidationInvalidSource, "decision log source is unsupported")
	}
	if unsafeSandboxNetworkProxyIdentifierMetadata(record.ID) {
		result.addError(index, "id", SandboxNetworkPolicyDecisionLogValidationUnsafeMetadata, "decision log id must be a safe identifier")
	}
	if unsafeSandboxNetworkProxyIdentifierMetadata(record.ProxySessionID) {
		result.addError(index, "proxySessionId", SandboxNetworkPolicyDecisionLogValidationUnsafeMetadata, "decision log proxy session id must be a safe identifier")
	}
	if record.Outcome == "" {
		result.addError(index, "outcome", SandboxNetworkPolicyDecisionLogValidationMissingRequiredField, "decision log outcome is required")
	} else if !validSandboxNetworkPolicyDecisionOutcome(record.Outcome) {
		result.addError(index, "outcome", SandboxNetworkPolicyDecisionLogValidationInvalidOutcome, "decision log outcome is unsupported")
	}
	if record.ReasonCode != "" && !validSandboxNetworkPolicyDecisionReasonCode(record.ReasonCode) {
		result.addError(index, "reasonCode", SandboxNetworkPolicyDecisionLogValidationInvalidReasonCode, "decision log reason code is unsupported")
	}
	if record.RuleKind != "" && !validSandboxNetworkPolicyRuleKind(record.RuleKind) {
		result.addError(index, "ruleKind", SandboxNetworkPolicyDecisionLogValidationInvalidRuleKind, "decision log rule kind is unsupported")
	}
	if record.PolicyPreset != "" && !validSandboxNetworkPolicyPreset(record.PolicyPreset) {
		result.addError(index, "policyPreset", SandboxNetworkPolicyDecisionLogValidationInvalidPolicyPreset, "decision log policy preset is unsupported")
	}
	if record.PolicySnapshot != nil {
		if record.PolicySnapshot.ID == "" {
			result.addError(index, "policySnapshot.id", SandboxNetworkPolicyDecisionLogValidationMissingRequiredField, "policy snapshot id is required")
		} else if unsafeSandboxNetworkProxyIdentifierMetadata(record.PolicySnapshot.ID) {
			result.addError(index, "policySnapshot.id", SandboxNetworkPolicyDecisionLogValidationUnsafeMetadata, "policy snapshot id must be a safe identifier")
		}
		if unsafeSandboxNetworkProxyIdentifierMetadata(record.PolicySnapshot.Version) {
			result.addError(index, "policySnapshot.version", SandboxNetworkPolicyDecisionLogValidationUnsafeMetadata, "policy snapshot version must be a safe identifier")
		}
		if unsafeSandboxNetworkProxyIdentifierMetadata(record.PolicySnapshot.RuleSetID) {
			result.addError(index, "policySnapshot.ruleSetId", SandboxNetworkPolicyDecisionLogValidationUnsafeMetadata, "policy snapshot rule set id must be a safe identifier")
		}
		if record.PolicySnapshot.Preset != "" && !validSandboxNetworkPolicyPreset(record.PolicySnapshot.Preset) {
			result.addError(index, "policySnapshot.preset", SandboxNetworkPolicyDecisionLogValidationInvalidPolicyPreset, "policy snapshot preset is unsupported")
		}
	}
	if record.Request != nil {
		if record.Request.DestinationCategory != "" && !validSandboxNetworkPolicyDestinationCategory(record.Request.DestinationCategory) {
			result.addError(index, "request.destinationCategory", SandboxNetworkPolicyDecisionLogValidationInvalidDestination, "decision log destination category is unsupported")
		}
		if unsafeSandboxNetworkProxyIdentifierMetadata(record.Request.ID) {
			result.addError(index, "request.id", SandboxNetworkPolicyDecisionLogValidationUnsafeRequestMetadata, "decision log request id must be a safe identifier")
		}
		if unsafeSandboxNetworkProxyIdentifierMetadata(record.Request.Operation) {
			result.addError(index, "request.operation", SandboxNetworkPolicyDecisionLogValidationUnsafeRequestMetadata, "decision log request operation must be a safe operation label")
		}
	}
	if record.EnforcementMode != "" && !validSandboxNetworkProxyEnforcementMode(record.EnforcementMode) {
		result.addError(index, "enforcementMode", SandboxNetworkPolicyDecisionLogValidationInvalidEnforcement, "decision log enforcement mode is unsupported")
	}
	if record.Enforced != nil &&
		*record.Enforced &&
		!sandboxNetworkPolicyModeCanEnforce(record.EnforcementMode) {
		result.addError(index, "enforced", SandboxNetworkPolicyDecisionLogValidationInvalidEnforcementClaim, "decision log cannot claim enforcement without explicit enforcing metadata")
	}
}

func unsafeSandboxNetworkProxyIdentifierMetadata(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && sanitizeSandboxNetworkProxyIdentifier(value) != value
}

func validSandboxNetworkPolicyDecisionSource(source SandboxNetworkPolicyDecisionSource) bool {
	switch source {
	case SandboxNetworkPolicyDecisionSourceRun,
		SandboxNetworkPolicyDecisionSourceAuto,
		SandboxNetworkPolicyDecisionSourceFactory,
		SandboxNetworkPolicyDecisionSourceWorker:
		return true
	default:
		return false
	}
}

func validSandboxNetworkPolicyDecisionOutcome(outcome SandboxNetworkPolicyDecisionOutcome) bool {
	switch outcome {
	case SandboxNetworkPolicyDecisionOutcomeAllowed,
		SandboxNetworkPolicyDecisionOutcomeDenied,
		SandboxNetworkPolicyDecisionOutcomeDowngraded,
		SandboxNetworkPolicyDecisionOutcomeAuditOnly:
		return true
	default:
		return false
	}
}

func validSandboxNetworkPolicyDecisionReasonCode(reason SandboxNetworkPolicyDecisionReasonCode) bool {
	switch reason {
	case SandboxNetworkPolicyDecisionReasonUnknown,
		SandboxNetworkPolicyDecisionReasonMatchedAllowRule,
		SandboxNetworkPolicyDecisionReasonMatchedDenyRule,
		SandboxNetworkPolicyDecisionReasonDefaultAllow,
		SandboxNetworkPolicyDecisionReasonDefaultDeny,
		SandboxNetworkPolicyDecisionReasonPolicyDisabled,
		SandboxNetworkPolicyDecisionReasonPolicyDowngraded,
		SandboxNetworkPolicyDecisionReasonEnforcementUnsupported,
		SandboxNetworkPolicyDecisionReasonAuditOnly:
		return true
	default:
		return false
	}
}

func validSandboxNetworkPolicyDestinationCategory(category SandboxNetworkPolicyDestinationCategory) bool {
	switch category {
	case SandboxNetworkPolicyDestinationPublicInternet,
		SandboxNetworkPolicyDestinationPrivateNetwork,
		SandboxNetworkPolicyDestinationMetadataService,
		SandboxNetworkPolicyDestinationLoopback,
		SandboxNetworkPolicyDestinationUnixSocket,
		SandboxNetworkPolicyDestinationUnknown:
		return true
	default:
		return false
	}
}

func validSandboxNetworkProxyEnforcementMode(mode string) bool {
	switch mode {
	case SandboxNetworkEnforcementModeNone,
		SandboxNetworkEnforcementModeBestEffort,
		SandboxNetworkEnforcementModeProxy,
		SandboxNetworkEnforcementModeFirewall,
		SandboxNetworkEnforcementModeRuntime,
		SandboxNetworkEnforcementModeProxyFirewall:
		return true
	default:
		return false
	}
}

func (r *SandboxNetworkProxyValidationResult) addError(field string, code SandboxNetworkProxyValidationCode, message string) {
	r.Errors = append(r.Errors, SandboxNetworkProxyValidationError{
		Code:    code,
		Field:   field,
		Message: message,
	})
}

func (r *SandboxNetworkPolicyDecisionLogValidationResult) addError(index int, field string, code SandboxNetworkPolicyDecisionLogValidationCode, message string) {
	r.Errors = append(r.Errors, SandboxNetworkPolicyDecisionLogValidationError{
		Code:        code,
		RecordIndex: index,
		Field:       field,
		Message:     message,
	})
}
