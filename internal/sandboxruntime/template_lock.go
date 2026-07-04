package sandboxruntime

import (
	"encoding/json"
	"strings"
	"time"
)

const (
	runtimeTemplateLockSourceKindLocalFile         = "local_file"
	runtimeTemplateLockSourceKindOCIArtifact       = "oci_artifact"
	runtimeTemplateLockSourceKindTemplateReference = "template_reference"
	runtimeTemplateLockSourceKindRuntimeImage      = "runtime_image"
	runtimeTemplateLockSourceKindSourceArtifact    = "source_artifact"

	runtimeTemplateLockReferenceKindLocal       = "local"
	runtimeTemplateLockReferenceKindOCIArtifact = "oci_artifact"
	runtimeTemplateLockReferenceKindOCIImage    = "oci_image"
	runtimeTemplateLockReferenceKindGit         = "git"
	runtimeTemplateLockReferenceKindInline      = "inline"

	runtimeTemplateLockStatusLocked     = "locked"
	runtimeTemplateLockStatusUnresolved = "unresolved"

	runtimeTemplateTrustPolicyModeStrict   = "strict"
	runtimeTemplateTrustPolicyModeAdvisory = "advisory"

	runtimeTemplateTrustPolicyDecisionTrusted     = "trusted"
	runtimeTemplateTrustPolicyDecisionRejected    = "rejected"
	runtimeTemplateTrustPolicyDecisionAdvisory    = "advisory"
	runtimeTemplateTrustPolicyDecisionUnavailable = "unavailable"

	runtimeTemplateTrustPolicyCodeMutableReference       = "mutable_reference"
	runtimeTemplateTrustPolicyCodeMissingDigestPin       = "missing_digest_pin"
	runtimeTemplateTrustPolicyCodeUnresolvedLockEntry    = "unresolved_lock_entry"
	runtimeTemplateTrustPolicyCodeLockProvenanceMismatch = "lock_provenance_mismatch"
	runtimeTemplateTrustPolicyCodeUnsupportedSource      = "unsupported_source"
	runtimeTemplateTrustPolicyCodeResolverUnavailable    = "resolver_unavailable"
)

const runtimeTemplateLockMaxWarningCodes = 8

// RuntimeTemplateLockMetadata mirrors the durable template lock JSON shape in
// internal/sandbox while keeping this root runtime package stdlib-only.
type RuntimeTemplateLockMetadata struct {
	Document          *RuntimeTemplateLockEntryMetadata   `json:"document,omitempty"`
	TemplateReference *RuntimeTemplateLockEntryMetadata   `json:"templateReference,omitempty"`
	RuntimeImage      *RuntimeTemplateLockEntryMetadata   `json:"runtimeImage,omitempty"`
	SourceArtifact    *RuntimeTemplateLockEntryMetadata   `json:"sourceArtifact,omitempty"`
	TrustPolicy       *RuntimeTemplateTrustPolicyMetadata `json:"trustPolicy,omitempty"`
}

// RuntimeTemplateLockEntryMetadata preserves only bounded identity and reason
// labels for runtime-local metadata JSON.
type RuntimeTemplateLockEntryMetadata struct {
	SourceKind      string   `json:"sourceKind,omitempty"`
	ReferenceKind   string   `json:"referenceKind,omitempty"`
	Status          string   `json:"status,omitempty"`
	DigestAlgorithm string   `json:"digestAlgorithm,omitempty"`
	DigestValue     string   `json:"digestValue,omitempty"`
	SizeBytes       int64    `json:"sizeBytes,omitempty"`
	LockedAt        string   `json:"lockedAt,omitempty"`
	WarningCodes    []string `json:"warningCodes,omitempty"`
	ReasonCode      string   `json:"reasonCode,omitempty"`
}

// RuntimeTemplateTrustPolicyMetadata carries bounded policy outcome labels for
// runtime selection callers without source refs, paths, endpoints, or secrets.
type RuntimeTemplateTrustPolicyMetadata struct {
	Mode            string   `json:"mode,omitempty"`
	Decision        string   `json:"decision,omitempty"`
	SourceKind      string   `json:"sourceKind,omitempty"`
	ReferenceKind   string   `json:"referenceKind,omitempty"`
	Status          string   `json:"status,omitempty"`
	DigestAlgorithm string   `json:"digestAlgorithm,omitempty"`
	DigestValue     string   `json:"digestValue,omitempty"`
	WarningCodes    []string `json:"warningCodes,omitempty"`
	ErrorCodes      []string `json:"errorCodes,omitempty"`
	ReasonCodes     []string `json:"reasonCodes,omitempty"`
}

// SanitizeRuntimeTemplateLockMetadata returns a durable-safe copy of runtime
// template lock metadata, or nil when no safe lock information remains.
func SanitizeRuntimeTemplateLockMetadata(metadata *RuntimeTemplateLockMetadata) *RuntimeTemplateLockMetadata {
	if metadata == nil {
		return nil
	}
	sanitized := &RuntimeTemplateLockMetadata{
		Document:          sanitizeRuntimeTemplateLockEntryMetadata(metadata.Document),
		TemplateReference: sanitizeRuntimeTemplateLockEntryMetadata(metadata.TemplateReference),
		RuntimeImage:      sanitizeRuntimeTemplateLockEntryMetadata(metadata.RuntimeImage),
		SourceArtifact:    sanitizeRuntimeTemplateLockEntryMetadata(metadata.SourceArtifact),
		TrustPolicy:       sanitizeRuntimeTemplateTrustPolicyMetadata(metadata.TrustPolicy),
	}
	if sanitized.Document == nil &&
		sanitized.TemplateReference == nil &&
		sanitized.RuntimeImage == nil &&
		sanitized.SourceArtifact == nil &&
		sanitized.TrustPolicy == nil {
		return nil
	}
	return sanitized
}

func (metadata RuntimeTemplateLockMetadata) MarshalJSON() ([]byte, error) {
	type runtimeTemplateLockMetadataJSON RuntimeTemplateLockMetadata
	sanitized := SanitizeRuntimeTemplateLockMetadata(&metadata)
	if sanitized == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(runtimeTemplateLockMetadataJSON(*sanitized))
}

func (metadata *RuntimeTemplateLockMetadata) UnmarshalJSON(data []byte) error {
	type runtimeTemplateLockMetadataJSON RuntimeTemplateLockMetadata
	var decoded runtimeTemplateLockMetadataJSON
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	sanitized := SanitizeRuntimeTemplateLockMetadata((*RuntimeTemplateLockMetadata)(&decoded))
	if sanitized == nil {
		*metadata = RuntimeTemplateLockMetadata{}
		return nil
	}
	*metadata = *sanitized
	return nil
}

func (metadata RuntimeMetadata) MarshalJSON() ([]byte, error) {
	type runtimeMetadataJSON RuntimeMetadata
	encoded := runtimeMetadataJSON(metadata)
	encoded.CredentialDelivery = SanitizeRuntimeCredentialDeliveryMetadata(metadata.CredentialDelivery)
	encoded.TemplateLock = SanitizeRuntimeTemplateLockMetadata(metadata.TemplateLock)
	return json.Marshal(encoded)
}

func (metadata *RuntimeMetadata) UnmarshalJSON(data []byte) error {
	type runtimeMetadataJSON RuntimeMetadata
	var decoded runtimeMetadataJSON
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	decoded.CredentialDelivery = SanitizeRuntimeCredentialDeliveryMetadata(decoded.CredentialDelivery)
	decoded.TemplateLock = SanitizeRuntimeTemplateLockMetadata(decoded.TemplateLock)
	*metadata = RuntimeMetadata(decoded)
	return nil
}

// SetTemplateLock attaches sanitized template lock metadata to runtime metadata.
func (metadata *RuntimeMetadata) SetTemplateLock(lock *RuntimeTemplateLockMetadata) {
	if metadata == nil {
		return
	}
	metadata.TemplateLock = SanitizeRuntimeTemplateLockMetadata(lock)
}

// CloneRuntimeTemplateLockMetadata returns a sanitized copy of runtime-local
// template lock metadata for durable runtime surfaces.
func CloneRuntimeTemplateLockMetadata(metadata *RuntimeTemplateLockMetadata) *RuntimeTemplateLockMetadata {
	return SanitizeRuntimeTemplateLockMetadata(metadata)
}

func sanitizeRuntimeTemplateLockEntryMetadata(entry *RuntimeTemplateLockEntryMetadata) *RuntimeTemplateLockEntryMetadata {
	if entry == nil {
		return nil
	}
	sanitized := &RuntimeTemplateLockEntryMetadata{
		SourceKind:    sanitizeRuntimeTemplateLockSourceKind(entry.SourceKind),
		ReferenceKind: sanitizeRuntimeTemplateLockReferenceKind(entry.ReferenceKind),
		Status:        sanitizeRuntimeTemplateLockStatus(entry.Status),
		SizeBytes:     sanitizeRuntimeTemplateLockSizeBytes(entry.SizeBytes),
		LockedAt:      sanitizeRuntimeTemplateLockTimestamp(entry.LockedAt),
		WarningCodes:  sanitizeRuntimeTemplateLockWarningCodes(entry.WarningCodes),
		ReasonCode:    sanitizeRuntimeTemplateLockReasonCode(entry.ReasonCode),
	}
	if sanitized.Status == runtimeTemplateLockStatusLocked {
		sanitized.DigestAlgorithm, sanitized.DigestValue = sanitizeRuntimeTemplateLockDigest(entry.DigestAlgorithm, entry.DigestValue)
	}
	if sanitized.SourceKind == "" &&
		sanitized.ReferenceKind == "" &&
		sanitized.Status == "" &&
		sanitized.DigestAlgorithm == "" &&
		sanitized.DigestValue == "" &&
		sanitized.SizeBytes == 0 &&
		sanitized.LockedAt == "" &&
		len(sanitized.WarningCodes) == 0 &&
		sanitized.ReasonCode == "" {
		return nil
	}
	return sanitized
}

func sanitizeRuntimeTemplateTrustPolicyMetadata(policy *RuntimeTemplateTrustPolicyMetadata) *RuntimeTemplateTrustPolicyMetadata {
	if policy == nil {
		return nil
	}
	sanitized := &RuntimeTemplateTrustPolicyMetadata{
		Mode:          sanitizeRuntimeTemplateTrustPolicyMode(policy.Mode),
		Decision:      sanitizeRuntimeTemplateTrustPolicyDecision(policy.Decision),
		SourceKind:    sanitizeRuntimeTemplateLockSourceKind(policy.SourceKind),
		ReferenceKind: sanitizeRuntimeTemplateLockReferenceKind(policy.ReferenceKind),
		Status:        sanitizeRuntimeTemplateLockStatus(policy.Status),
		WarningCodes:  sanitizeRuntimeTemplateTrustPolicyCodes(policy.WarningCodes),
		ErrorCodes:    sanitizeRuntimeTemplateTrustPolicyCodes(policy.ErrorCodes),
		ReasonCodes:   sanitizeRuntimeTemplateLockReasonCodes(policy.ReasonCodes),
	}
	if sanitized.Status == runtimeTemplateLockStatusLocked {
		sanitized.DigestAlgorithm, sanitized.DigestValue = sanitizeRuntimeTemplateLockDigest(policy.DigestAlgorithm, policy.DigestValue)
	}
	if sanitized.Mode == "" &&
		sanitized.Decision == "" &&
		sanitized.SourceKind == "" &&
		sanitized.ReferenceKind == "" &&
		sanitized.Status == "" &&
		sanitized.DigestAlgorithm == "" &&
		sanitized.DigestValue == "" &&
		len(sanitized.WarningCodes) == 0 &&
		len(sanitized.ErrorCodes) == 0 &&
		len(sanitized.ReasonCodes) == 0 {
		return nil
	}
	return sanitized
}

func sanitizeRuntimeTemplateLockSourceKind(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case runtimeTemplateLockSourceKindLocalFile:
		return runtimeTemplateLockSourceKindLocalFile
	case runtimeTemplateLockSourceKindOCIArtifact:
		return runtimeTemplateLockSourceKindOCIArtifact
	case runtimeTemplateLockSourceKindTemplateReference:
		return runtimeTemplateLockSourceKindTemplateReference
	case runtimeTemplateLockSourceKindRuntimeImage:
		return runtimeTemplateLockSourceKindRuntimeImage
	case runtimeTemplateLockSourceKindSourceArtifact:
		return runtimeTemplateLockSourceKindSourceArtifact
	default:
		return ""
	}
}

func sanitizeRuntimeTemplateLockReferenceKind(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case runtimeTemplateLockReferenceKindLocal:
		return runtimeTemplateLockReferenceKindLocal
	case runtimeTemplateLockReferenceKindOCIArtifact:
		return runtimeTemplateLockReferenceKindOCIArtifact
	case runtimeTemplateLockReferenceKindOCIImage:
		return runtimeTemplateLockReferenceKindOCIImage
	case runtimeTemplateLockReferenceKindGit:
		return runtimeTemplateLockReferenceKindGit
	case runtimeTemplateLockReferenceKindInline:
		return runtimeTemplateLockReferenceKindInline
	default:
		return ""
	}
}

func sanitizeRuntimeTemplateLockStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case runtimeTemplateLockStatusLocked:
		return runtimeTemplateLockStatusLocked
	case runtimeTemplateLockStatusUnresolved:
		return runtimeTemplateLockStatusUnresolved
	default:
		return ""
	}
}

func sanitizeRuntimeTemplateTrustPolicyMode(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case runtimeTemplateTrustPolicyModeStrict:
		return runtimeTemplateTrustPolicyModeStrict
	case runtimeTemplateTrustPolicyModeAdvisory:
		return runtimeTemplateTrustPolicyModeAdvisory
	default:
		return ""
	}
}

func sanitizeRuntimeTemplateTrustPolicyDecision(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case runtimeTemplateTrustPolicyDecisionTrusted:
		return runtimeTemplateTrustPolicyDecisionTrusted
	case runtimeTemplateTrustPolicyDecisionRejected:
		return runtimeTemplateTrustPolicyDecisionRejected
	case runtimeTemplateTrustPolicyDecisionAdvisory:
		return runtimeTemplateTrustPolicyDecisionAdvisory
	case runtimeTemplateTrustPolicyDecisionUnavailable:
		return runtimeTemplateTrustPolicyDecisionUnavailable
	default:
		return ""
	}
}

func sanitizeRuntimeTemplateLockDigest(algorithm string, value string) (string, string) {
	normalizedAlgorithm := strings.ToLower(strings.TrimSpace(algorithm))
	normalizedValue := strings.ToLower(strings.TrimSpace(value))
	if !validRuntimeTemplateLockDigestAlgorithm(normalizedAlgorithm) {
		return "", ""
	}
	if len(normalizedValue) != runtimeTemplateLockDigestLength(normalizedAlgorithm) {
		return "", ""
	}
	for _, r := range normalizedValue {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return "", ""
		}
	}
	return normalizedAlgorithm, normalizedValue
}

func validRuntimeTemplateLockDigestAlgorithm(algorithm string) bool {
	switch algorithm {
	case "sha256", "sha384", "sha512":
		return true
	default:
		return false
	}
}

func runtimeTemplateLockDigestLength(algorithm string) int {
	switch algorithm {
	case "sha256":
		return 64
	case "sha384":
		return 96
	case "sha512":
		return 128
	default:
		return 0
	}
}

func sanitizeRuntimeTemplateLockSizeBytes(value int64) int64 {
	if value <= 0 {
		return 0
	}
	return value
}

func sanitizeRuntimeTemplateLockTimestamp(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	parsed, err := time.Parse(time.RFC3339, trimmed)
	if err != nil {
		return ""
	}
	return parsed.UTC().Format(time.RFC3339)
}

func sanitizeRuntimeTemplateLockReasonCode(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if runtimeTemplateLockAllowedReasonCode(normalized) {
		return normalized
	}
	return ""
}

func sanitizeRuntimeTemplateLockWarningCodes(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sanitized := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		code := sanitizeRuntimeTemplateLockReasonCode(value)
		if code == "" || seen[code] {
			continue
		}
		sanitized = append(sanitized, code)
		seen[code] = true
		if len(sanitized) == runtimeTemplateLockMaxWarningCodes {
			break
		}
	}
	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
}

func sanitizeRuntimeTemplateLockReasonCodes(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sanitized := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		code := sanitizeRuntimeTemplateLockReasonCode(value)
		if code == "" || seen[code] {
			continue
		}
		sanitized = append(sanitized, code)
		seen[code] = true
		if len(sanitized) == runtimeTemplateLockMaxWarningCodes {
			break
		}
	}
	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
}

func sanitizeRuntimeTemplateTrustPolicyCodes(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sanitized := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		code := sanitizeRuntimeTemplateTrustPolicyCode(value)
		if code == "" || seen[code] {
			continue
		}
		sanitized = append(sanitized, code)
		seen[code] = true
		if len(sanitized) == runtimeTemplateLockMaxWarningCodes {
			break
		}
	}
	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
}

func sanitizeRuntimeTemplateTrustPolicyCode(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case runtimeTemplateTrustPolicyCodeMutableReference,
		runtimeTemplateTrustPolicyCodeMissingDigestPin,
		runtimeTemplateTrustPolicyCodeUnresolvedLockEntry,
		runtimeTemplateTrustPolicyCodeLockProvenanceMismatch,
		runtimeTemplateTrustPolicyCodeUnsupportedSource,
		runtimeTemplateTrustPolicyCodeResolverUnavailable:
		return normalized
	default:
		return ""
	}
}

func runtimeTemplateLockAllowedReasonCode(code string) bool {
	switch code {
	case "document_digest",
		"template_reference_digest",
		"runtime_image_digest",
		"source_artifact_digest",
		"immutable_digest",
		"mutable_reference",
		"unresolved_mutable_reference",
		"resolver_unavailable",
		"unsupported_source":
		return true
	default:
		return false
	}
}
