package acquisition

import (
	"encoding/json"
	"strings"
)

const trustPolicyMaxMessageBytes = 160

func (finding TrustPolicyError) MarshalJSON() ([]byte, error) {
	type trustPolicyErrorJSON TrustPolicyError
	sanitized := sanitizeTrustPolicyError(finding)
	return json.Marshal(trustPolicyErrorJSON(sanitized))
}

func (finding *TrustPolicyError) UnmarshalJSON(data []byte) error {
	type trustPolicyErrorJSON TrustPolicyError
	var decoded trustPolicyErrorJSON
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*finding = sanitizeTrustPolicyError(TrustPolicyError(decoded))
	return nil
}

func (finding TrustPolicyWarning) MarshalJSON() ([]byte, error) {
	type trustPolicyWarningJSON TrustPolicyWarning
	sanitized := sanitizeTrustPolicyWarning(finding)
	return json.Marshal(trustPolicyWarningJSON(sanitized))
}

func (finding *TrustPolicyWarning) UnmarshalJSON(data []byte) error {
	type trustPolicyWarningJSON TrustPolicyWarning
	var decoded trustPolicyWarningJSON
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*finding = sanitizeTrustPolicyWarning(TrustPolicyWarning(decoded))
	return nil
}

func sanitizeTrustPolicyError(finding TrustPolicyError) TrustPolicyError {
	sanitized := TrustPolicyError{
		Code:           sanitizeTrustPolicyErrorCode(finding.Code),
		Field:          sanitizeTrustPolicyFindingField(finding.Field),
		ReferenceField: sanitizeTrustPolicyReferenceField(finding.ReferenceField),
		SourceKind:     sanitizeTrustPolicySourceKind(finding.SourceKind),
		ReasonCode:     sanitizeTrustPolicyReasonCode(finding.ReasonCode),
		Message:        sanitizeTrustPolicyFindingMessage(finding.Message),
	}
	if finding.ReferenceIndex != nil && *finding.ReferenceIndex >= 0 {
		index := *finding.ReferenceIndex
		sanitized.ReferenceIndex = &index
	}
	return sanitized
}

func sanitizeTrustPolicyWarning(finding TrustPolicyWarning) TrustPolicyWarning {
	sanitized := TrustPolicyWarning{
		Code:           sanitizeTrustPolicyWarningCode(finding.Code),
		Field:          sanitizeTrustPolicyFindingField(finding.Field),
		ReferenceField: sanitizeTrustPolicyReferenceField(finding.ReferenceField),
		SourceKind:     sanitizeTrustPolicySourceKind(finding.SourceKind),
		ReasonCode:     sanitizeTrustPolicyReasonCode(finding.ReasonCode),
		Message:        sanitizeTrustPolicyFindingMessage(finding.Message),
	}
	if finding.ReferenceIndex != nil && *finding.ReferenceIndex >= 0 {
		index := *finding.ReferenceIndex
		sanitized.ReferenceIndex = &index
	}
	return sanitized
}

func sanitizeTrustPolicyErrorCode(code TrustPolicyErrorCode) TrustPolicyErrorCode {
	switch code {
	case TrustPolicyErrorMutableReference,
		TrustPolicyErrorMissingDigestPin,
		TrustPolicyErrorUnresolvedLockEntry,
		TrustPolicyErrorLockProvenanceMismatch,
		TrustPolicyErrorUnsupportedSource,
		TrustPolicyErrorResolverUnavailable:
		return code
	default:
		return ""
	}
}

func sanitizeTrustPolicyWarningCode(code TrustPolicyWarningCode) TrustPolicyWarningCode {
	switch code {
	case TrustPolicyWarningMutableReference,
		TrustPolicyWarningMissingDigestPin,
		TrustPolicyWarningUnresolvedLockEntry,
		TrustPolicyWarningLockProvenanceMismatch,
		TrustPolicyWarningUnsupportedSource,
		TrustPolicyWarningResolverUnavailable:
		return code
	default:
		return ""
	}
}

func sanitizeTrustPolicyFindingField(field string) string {
	switch strings.TrimSpace(field) {
	case trustPolicyFieldRequiredReferences:
		return trustPolicyFieldRequiredReferences
	case trustPolicyFieldTemplateDocumentLock:
		return trustPolicyFieldTemplateDocumentLock
	case "provenance":
		return "provenance"
	default:
		return trustPolicyKnownReferenceField(field)
	}
}

func sanitizeTrustPolicyReferenceField(field string) string {
	return trustPolicyKnownReferenceField(field)
}

func sanitizeTrustPolicySourceKind(kind SourceKind) SourceKind {
	switch kind {
	case SourceKindLocalFile, SourceKindOCIArtifact:
		return kind
	default:
		return ""
	}
}

func sanitizeTrustPolicyReasonCode(code LockReasonCode) LockReasonCode {
	if templateProvenanceAllowedReasonCode(string(code)) {
		return code
	}
	return ""
}

func sanitizeTrustPolicyFindingMessage(message string) string {
	message = strings.Join(strings.Fields(strings.TrimSpace(message)), " ")
	if len(message) == 0 || len(message) > trustPolicyMaxMessageBytes {
		return ""
	}
	switch message {
	case trustPolicyMissingDigestMessage,
		trustPolicyUnresolvedLockMessage,
		trustPolicyMissingDocumentDigestMessage,
		trustPolicyProvenanceMismatchMessage,
		trustPolicyDocumentMismatchMessage,
		"resolver is unavailable":
		return message
	default:
		return ""
	}
}
