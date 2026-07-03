package sandbox

import (
	"encoding/json"
	"strings"
	"time"
)

const (
	SandboxTemplateLockSourceKindLocalFile         = "local_file"
	SandboxTemplateLockSourceKindOCIArtifact       = "oci_artifact"
	SandboxTemplateLockSourceKindTemplateReference = "template_reference"
	SandboxTemplateLockSourceKindRuntimeImage      = "runtime_image"
	SandboxTemplateLockSourceKindSourceArtifact    = "source_artifact"

	SandboxTemplateLockReferenceKindLocal       = "local"
	SandboxTemplateLockReferenceKindOCIArtifact = "oci_artifact"
	SandboxTemplateLockReferenceKindOCIImage    = "oci_image"
	SandboxTemplateLockReferenceKindGit         = "git"
	SandboxTemplateLockReferenceKindInline      = "inline"

	SandboxTemplateLockStatusLocked     = "locked"
	SandboxTemplateLockStatusUnresolved = "unresolved"

	SandboxTemplateLockReasonDocumentDigest             = "document_digest"
	SandboxTemplateLockReasonTemplateReferenceDigest    = "template_reference_digest"
	SandboxTemplateLockReasonRuntimeImageDigest         = "runtime_image_digest"
	SandboxTemplateLockReasonSourceArtifactDigest       = "source_artifact_digest"
	SandboxTemplateLockReasonImmutableDigest            = "immutable_digest"
	SandboxTemplateLockReasonMutableReference           = "mutable_reference"
	SandboxTemplateLockReasonUnresolvedMutableReference = "unresolved_mutable_reference"
	SandboxTemplateLockReasonResolverUnavailable        = "resolver_unavailable"
	SandboxTemplateLockReasonUnsupportedSource          = "unsupported_source"
)

const sandboxTemplateLockMaxWarningCodes = 8

// SandboxTemplateLockMetadata is the durable redaction-safe template
// acquisition lock shape shared by sandbox, execution, and factory records.
type SandboxTemplateLockMetadata struct {
	Document          *SandboxTemplateLockEntryMetadata `json:"document,omitempty"`
	TemplateReference *SandboxTemplateLockEntryMetadata `json:"templateReference,omitempty"`
	RuntimeImage      *SandboxTemplateLockEntryMetadata `json:"runtimeImage,omitempty"`
	SourceArtifact    *SandboxTemplateLockEntryMetadata `json:"sourceArtifact,omitempty"`
}

// SandboxTemplateLockEntryMetadata preserves only bounded identity and reason
// labels. It must not grow raw references, local paths, endpoints, or secrets.
type SandboxTemplateLockEntryMetadata struct {
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

// SanitizeSandboxTemplateLockMetadata returns a durable-safe copy of template
// lock metadata, or nil when no safe lock information remains.
func SanitizeSandboxTemplateLockMetadata(metadata *SandboxTemplateLockMetadata) *SandboxTemplateLockMetadata {
	if metadata == nil {
		return nil
	}
	sanitized := &SandboxTemplateLockMetadata{
		Document:          sanitizeSandboxTemplateLockEntryMetadata(metadata.Document),
		TemplateReference: sanitizeSandboxTemplateLockEntryMetadata(metadata.TemplateReference),
		RuntimeImage:      sanitizeSandboxTemplateLockEntryMetadata(metadata.RuntimeImage),
		SourceArtifact:    sanitizeSandboxTemplateLockEntryMetadata(metadata.SourceArtifact),
	}
	if sanitized.Document == nil &&
		sanitized.TemplateReference == nil &&
		sanitized.RuntimeImage == nil &&
		sanitized.SourceArtifact == nil {
		return nil
	}
	return sanitized
}

func (metadata SandboxTemplateLockMetadata) MarshalJSON() ([]byte, error) {
	type sandboxTemplateLockMetadataJSON SandboxTemplateLockMetadata
	sanitized := SanitizeSandboxTemplateLockMetadata(&metadata)
	if sanitized == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(sandboxTemplateLockMetadataJSON(*sanitized))
}

func (metadata *SandboxTemplateLockMetadata) UnmarshalJSON(data []byte) error {
	type sandboxTemplateLockMetadataJSON SandboxTemplateLockMetadata
	var decoded sandboxTemplateLockMetadataJSON
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	sanitized := SanitizeSandboxTemplateLockMetadata((*SandboxTemplateLockMetadata)(&decoded))
	if sanitized == nil {
		*metadata = SandboxTemplateLockMetadata{}
		return nil
	}
	*metadata = *sanitized
	return nil
}

func (state SandboxRuntimeState) MarshalJSON() ([]byte, error) {
	type sandboxRuntimeStateJSON SandboxRuntimeState
	encoded := sandboxRuntimeStateJSON(state)
	encoded.TemplateLock = SanitizeSandboxTemplateLockMetadata(state.TemplateLock)
	return json.Marshal(encoded)
}

func (state *SandboxRuntimeState) UnmarshalJSON(data []byte) error {
	type sandboxRuntimeStateJSON SandboxRuntimeState
	var decoded sandboxRuntimeStateJSON
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	decoded.TemplateLock = SanitizeSandboxTemplateLockMetadata(decoded.TemplateLock)
	*state = SandboxRuntimeState(decoded)
	return nil
}

// SetTemplateLock attaches sanitized template lock metadata to runtime state.
func (state *SandboxRuntimeState) SetTemplateLock(metadata *SandboxTemplateLockMetadata) {
	if state == nil {
		return
	}
	state.TemplateLock = SanitizeSandboxTemplateLockMetadata(metadata)
}

func sanitizeSandboxTemplateLockEntryMetadata(entry *SandboxTemplateLockEntryMetadata) *SandboxTemplateLockEntryMetadata {
	if entry == nil {
		return nil
	}
	sanitized := &SandboxTemplateLockEntryMetadata{
		SourceKind:    sanitizeSandboxTemplateLockSourceKind(entry.SourceKind),
		ReferenceKind: sanitizeSandboxTemplateLockReferenceKind(entry.ReferenceKind),
		Status:        sanitizeSandboxTemplateLockStatus(entry.Status),
		SizeBytes:     sanitizeSandboxTemplateLockSizeBytes(entry.SizeBytes),
		LockedAt:      sanitizeSandboxTemplateLockTimestamp(entry.LockedAt),
		WarningCodes:  sanitizeSandboxTemplateLockWarningCodes(entry.WarningCodes),
		ReasonCode:    sanitizeSandboxTemplateLockReasonCode(entry.ReasonCode),
	}
	if sanitized.Status == SandboxTemplateLockStatusLocked {
		sanitized.DigestAlgorithm, sanitized.DigestValue = sanitizeSandboxTemplateLockDigest(entry.DigestAlgorithm, entry.DigestValue)
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

func sanitizeSandboxTemplateLockSourceKind(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case SandboxTemplateLockSourceKindLocalFile:
		return SandboxTemplateLockSourceKindLocalFile
	case SandboxTemplateLockSourceKindOCIArtifact:
		return SandboxTemplateLockSourceKindOCIArtifact
	case SandboxTemplateLockSourceKindTemplateReference:
		return SandboxTemplateLockSourceKindTemplateReference
	case SandboxTemplateLockSourceKindRuntimeImage:
		return SandboxTemplateLockSourceKindRuntimeImage
	case SandboxTemplateLockSourceKindSourceArtifact:
		return SandboxTemplateLockSourceKindSourceArtifact
	default:
		return ""
	}
}

func sanitizeSandboxTemplateLockReferenceKind(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case SandboxTemplateLockReferenceKindLocal:
		return SandboxTemplateLockReferenceKindLocal
	case SandboxTemplateLockReferenceKindOCIArtifact:
		return SandboxTemplateLockReferenceKindOCIArtifact
	case SandboxTemplateLockReferenceKindOCIImage:
		return SandboxTemplateLockReferenceKindOCIImage
	case SandboxTemplateLockReferenceKindGit:
		return SandboxTemplateLockReferenceKindGit
	case SandboxTemplateLockReferenceKindInline:
		return SandboxTemplateLockReferenceKindInline
	default:
		return ""
	}
}

func sanitizeSandboxTemplateLockStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case SandboxTemplateLockStatusLocked:
		return SandboxTemplateLockStatusLocked
	case SandboxTemplateLockStatusUnresolved:
		return SandboxTemplateLockStatusUnresolved
	default:
		return ""
	}
}

func sanitizeSandboxTemplateLockDigest(algorithm string, value string) (string, string) {
	normalizedAlgorithm := strings.ToLower(strings.TrimSpace(algorithm))
	normalizedValue := strings.ToLower(strings.TrimSpace(value))
	if !validSandboxTemplateLockDigestAlgorithm(normalizedAlgorithm) {
		return "", ""
	}
	if len(normalizedValue) != sandboxTemplateLockDigestLength(normalizedAlgorithm) {
		return "", ""
	}
	for _, r := range normalizedValue {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return "", ""
		}
	}
	return normalizedAlgorithm, normalizedValue
}

func validSandboxTemplateLockDigestAlgorithm(algorithm string) bool {
	switch algorithm {
	case "sha256", "sha384", "sha512":
		return true
	default:
		return false
	}
}

func sandboxTemplateLockDigestLength(algorithm string) int {
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

func sanitizeSandboxTemplateLockSizeBytes(value int64) int64 {
	if value <= 0 {
		return 0
	}
	return value
}

func sanitizeSandboxTemplateLockTimestamp(value string) string {
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

func sanitizeSandboxTemplateLockReasonCode(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if sandboxTemplateLockAllowedReasonCode(normalized) {
		return normalized
	}
	return ""
}

func sanitizeSandboxTemplateLockWarningCodes(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sanitized := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		code := sanitizeSandboxTemplateLockReasonCode(value)
		if code == "" || seen[code] {
			continue
		}
		sanitized = append(sanitized, code)
		seen[code] = true
		if len(sanitized) == sandboxTemplateLockMaxWarningCodes {
			break
		}
	}
	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
}

func sandboxTemplateLockAllowedReasonCode(code string) bool {
	switch code {
	case SandboxTemplateLockReasonDocumentDigest,
		SandboxTemplateLockReasonTemplateReferenceDigest,
		SandboxTemplateLockReasonRuntimeImageDigest,
		SandboxTemplateLockReasonSourceArtifactDigest,
		SandboxTemplateLockReasonImmutableDigest,
		SandboxTemplateLockReasonMutableReference,
		SandboxTemplateLockReasonUnresolvedMutableReference,
		SandboxTemplateLockReasonResolverUnavailable,
		SandboxTemplateLockReasonUnsupportedSource:
		return true
	default:
		return false
	}
}
