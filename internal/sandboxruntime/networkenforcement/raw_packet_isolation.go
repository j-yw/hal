package networkenforcement

import "encoding/json"

// RawPacketIsolationStatus distinguishes an exact mechanically verified
// runtime capability boundary from absent or stale metadata.
type RawPacketIsolationStatus string

const (
	RawPacketIsolationStatusVerified RawPacketIsolationStatus = "verified"
	RawPacketIsolationStatusAbsent   RawPacketIsolationStatus = "absent"
	RawPacketIsolationStatusStale    RawPacketIsolationStatus = "stale"
)

// RawPacketIsolationProof is safe public evidence that the exact correlated
// runtime generation cannot create raw packet sockets. It is deliberately
// separate from inspected firewall rules because an inet output hook cannot
// mediate AF_PACKET transmission.
type RawPacketIsolationProof struct {
	ID                  string                   `json:"id,omitempty"`
	Status              RawPacketIsolationStatus `json:"status,omitempty"`
	VerifiedAtUnixMilli int64                    `json:"verifiedAtUnixMilli,omitempty"`
	Correlation         *EnforcementCorrelation  `json:"correlation,omitempty"`
	ReasonCode          LifecycleReasonCode      `json:"reasonCode,omitempty"`
	WarningCodes        []LifecycleWarningCode   `json:"warningCodes,omitempty"`
}

// SanitizeRawPacketIsolationProof returns redaction-safe evidence and
// downgrades incomplete or unsafe verified claims to stale proof.
func SanitizeRawPacketIsolationProof(value RawPacketIsolationProof) RawPacketIsolationProof {
	correlation := sanitizeEnforcementCorrelationPtr(value.Correlation)
	sanitized := RawPacketIsolationProof{
		ID:                  sanitizeIdentifier(value.ID),
		Status:              sanitizeRawPacketIsolationStatus(value.Status),
		VerifiedAtUnixMilli: sanitizePositiveUnixMilli(value.VerifiedAtUnixMilli),
		Correlation:         correlation,
		ReasonCode:          sanitizeLifecycleReasonCode(value.ReasonCode),
		WarningCodes:        sanitizeLifecycleWarningCodeList(value.WarningCodes),
	}
	inputInvalid := (value.ID != "" && sanitized.ID == "") ||
		(value.Correlation != nil && correlation == nil) ||
		(value.VerifiedAtUnixMilli != 0 && sanitized.VerifiedAtUnixMilli == 0) ||
		len(value.WarningCodes) != len(sanitized.WarningCodes)
	if sanitized.Status == RawPacketIsolationStatusVerified &&
		(inputInvalid || sanitized.ID == "" || sanitized.VerifiedAtUnixMilli == 0 ||
			sanitized.Correlation == nil || !EnforcementCorrelationComplete(*sanitized.Correlation) ||
			sanitized.ReasonCode != LifecycleReasonRawPacketIsolationVerified || len(sanitized.WarningCodes) > 0) {
		sanitized.Status = RawPacketIsolationStatusStale
		sanitized.ReasonCode = LifecycleReasonProofMismatch
		sanitized.WarningCodes = appendLifecycleWarnings(sanitized.WarningCodes, LifecycleWarningProofMismatch)
	}
	return sanitized
}

func (value RawPacketIsolationProof) MarshalJSON() ([]byte, error) {
	type rawPacketIsolationProofJSON RawPacketIsolationProof
	return json.Marshal(rawPacketIsolationProofJSON(SanitizeRawPacketIsolationProof(value)))
}

func sanitizeRawPacketIsolationProofPtr(value *RawPacketIsolationProof) *RawPacketIsolationProof {
	if value == nil {
		return nil
	}
	sanitized := SanitizeRawPacketIsolationProof(*value)
	if rawPacketIsolationProofEmpty(sanitized) {
		return nil
	}
	return &sanitized
}

func rawPacketIsolationProofEmpty(value RawPacketIsolationProof) bool {
	return value.ID == "" && value.Status == "" && value.VerifiedAtUnixMilli == 0 &&
		value.Correlation == nil && value.ReasonCode == "" && len(value.WarningCodes) == 0
}

// RawPacketIsolationProofMatches reports whether sanitized verified proof is
// complete and belongs to the exact expected live generation.
func RawPacketIsolationProofMatches(value RawPacketIsolationProof, expected EnforcementCorrelation) bool {
	sanitized := SanitizeRawPacketIsolationProof(value)
	return sanitized.Status == RawPacketIsolationStatusVerified &&
		sanitized.ID != "" && sanitized.VerifiedAtUnixMilli > 0 &&
		sanitized.Correlation != nil &&
		EnforcementCorrelationsEqual(*sanitized.Correlation, expected) &&
		sanitized.ReasonCode == LifecycleReasonRawPacketIsolationVerified &&
		len(sanitized.WarningCodes) == 0
}

func sanitizeRawPacketIsolationStatus(value RawPacketIsolationStatus) RawPacketIsolationStatus {
	normalized := RawPacketIsolationStatus(normalizeEnum(string(value)))
	switch normalized {
	case RawPacketIsolationStatusVerified, RawPacketIsolationStatusAbsent, RawPacketIsolationStatusStale:
		return normalized
	default:
		return ""
	}
}
