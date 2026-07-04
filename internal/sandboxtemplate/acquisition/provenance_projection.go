package acquisition

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandboxtemplate"
)

const templateProvenanceMaxWarningCodes = 8

const (
	templateProvenanceSourceKindTemplateReference = "template_reference"
	templateProvenanceSourceKindRuntimeImage      = "runtime_image"
	templateProvenanceSourceKindSourceArtifact    = "source_artifact"
)

// TemplateProvenanceProjection is the additive redaction-safe acquisition
// provenance view for callers that need to audit template trust decisions.
type TemplateProvenanceProjection struct {
	Document          *TemplateProvenanceEntry `json:"document,omitempty"`
	TemplateReference *TemplateProvenanceEntry `json:"templateReference,omitempty"`
	RuntimeImage      *TemplateProvenanceEntry `json:"runtimeImage,omitempty"`
	SourceArtifact    *TemplateProvenanceEntry `json:"sourceArtifact,omitempty"`
}

// TemplateProvenanceEntry carries bounded lock identity only. It intentionally
// omits raw local paths, registry references, credential material, and
// annotations.
type TemplateProvenanceEntry struct {
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

// ProjectTemplateProvenance maps local or OCI acquisition lock metadata into a
// durable-safe four-role projection without fetching, pulling, cloning, or
// touching runtime startup surfaces.
func ProjectTemplateProvenance(lock TemplateLock) *TemplateProvenanceProjection {
	projection := &TemplateProvenanceProjection{
		Document: projectTemplateProvenanceDocument(lock),
	}
	for _, reference := range lock.References {
		switch strings.TrimSpace(reference.Field) {
		case "metadata.reference":
			if projection.TemplateReference == nil {
				projection.TemplateReference = projectTemplateProvenanceReference(reference, templateProvenanceSourceKindTemplateReference, LockReasonTemplateReferenceDigest)
			}
		case "runtime.image":
			if projection.RuntimeImage == nil {
				projection.RuntimeImage = projectTemplateProvenanceReference(reference, templateProvenanceSourceKindRuntimeImage, LockReasonRuntimeImageDigest)
			}
		case "workspace.ref":
			if projection.SourceArtifact == nil {
				projection.SourceArtifact = projectTemplateProvenanceReference(reference, templateProvenanceSourceKindSourceArtifact, LockReasonSourceArtifactDigest)
			}
		}
	}
	return SanitizeTemplateProvenanceProjection(projection)
}

// SanitizeTemplateProvenanceProjection returns a durable-safe projection copy,
// or nil when no safe provenance metadata remains.
func SanitizeTemplateProvenanceProjection(projection *TemplateProvenanceProjection) *TemplateProvenanceProjection {
	if projection == nil {
		return nil
	}
	sanitized := &TemplateProvenanceProjection{
		Document:          sanitizeTemplateProvenanceEntry(projection.Document),
		TemplateReference: sanitizeTemplateProvenanceEntry(projection.TemplateReference),
		RuntimeImage:      sanitizeTemplateProvenanceEntry(projection.RuntimeImage),
		SourceArtifact:    sanitizeTemplateProvenanceEntry(projection.SourceArtifact),
	}
	if sanitized.Document == nil &&
		sanitized.TemplateReference == nil &&
		sanitized.RuntimeImage == nil &&
		sanitized.SourceArtifact == nil {
		return nil
	}
	return sanitized
}

func (projection TemplateProvenanceProjection) MarshalJSON() ([]byte, error) {
	type templateProvenanceProjectionJSON TemplateProvenanceProjection
	sanitized := SanitizeTemplateProvenanceProjection(&projection)
	if sanitized == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(templateProvenanceProjectionJSON(*sanitized))
}

func (projection *TemplateProvenanceProjection) UnmarshalJSON(data []byte) error {
	type templateProvenanceProjectionJSON TemplateProvenanceProjection
	var decoded templateProvenanceProjectionJSON
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	sanitized := SanitizeTemplateProvenanceProjection((*TemplateProvenanceProjection)(&decoded))
	if sanitized == nil {
		*projection = TemplateProvenanceProjection{}
		return nil
	}
	*projection = *sanitized
	return nil
}

func projectTemplateProvenanceDocument(lock TemplateLock) *TemplateProvenanceEntry {
	status := lock.Document.Status
	if status == "" {
		status = lock.Status
	}
	entry := &TemplateProvenanceEntry{
		SourceKind:    string(lock.SourceKind),
		ReferenceKind: string(lock.ReferenceKind),
		Status:        string(status),
		SizeBytes:     lock.Document.SizeBytes,
		LockedAt:      projectTemplateProvenanceLockedAt(lock.Document.LockedAtUnixMillis),
		WarningCodes:  lockReasonCodesToStrings(lock.Warnings),
		ReasonCode:    string(lock.Document.ReasonCode),
	}
	if lock.Document.Digest != nil {
		entry.DigestAlgorithm = string(lock.Document.Digest.Algorithm)
		entry.DigestValue = lock.Document.Digest.Value
	}
	return entry
}

func projectTemplateProvenanceReference(reference ReferenceLock, sourceKind string, lockedReason LockReasonCode) *TemplateProvenanceEntry {
	entry := &TemplateProvenanceEntry{
		SourceKind:    sourceKind,
		ReferenceKind: string(reference.Kind),
		Status:        string(reference.Status),
		ReasonCode:    string(projectTemplateProvenanceReferenceReason(reference, lockedReason)),
	}
	if reference.Digest != nil {
		entry.DigestAlgorithm = string(reference.Digest.Algorithm)
		entry.DigestValue = reference.Digest.Value
	}
	return entry
}

func projectTemplateProvenanceReferenceReason(reference ReferenceLock, lockedReason LockReasonCode) LockReasonCode {
	if reference.Status == LockStatusLocked && reference.Digest != nil {
		return lockedReason
	}
	if reference.Status == LockStatusUnresolved && (reference.ReasonCode == "" || reference.ReasonCode == LockReasonMutableReference) {
		return LockReasonUnresolvedMutableReference
	}
	return reference.ReasonCode
}

func projectTemplateProvenanceLockedAt(unixMillis int64) string {
	if unixMillis <= 0 {
		return ""
	}
	return time.UnixMilli(unixMillis).UTC().Format(time.RFC3339)
}

func lockReasonCodesToStrings(codes []LockReasonCode) []string {
	if len(codes) == 0 {
		return nil
	}
	out := make([]string, 0, len(codes))
	for _, code := range codes {
		out = append(out, string(code))
	}
	return out
}

func sanitizeTemplateProvenanceEntry(entry *TemplateProvenanceEntry) *TemplateProvenanceEntry {
	if entry == nil {
		return nil
	}
	sanitized := &TemplateProvenanceEntry{
		SourceKind:    sanitizeTemplateProvenanceSourceKind(entry.SourceKind),
		ReferenceKind: sanitizeTemplateProvenanceReferenceKind(entry.ReferenceKind),
		Status:        sanitizeTemplateProvenanceStatus(entry.Status),
		SizeBytes:     sanitizeTemplateProvenanceSizeBytes(entry.SizeBytes),
		LockedAt:      sanitizeTemplateProvenanceTimestamp(entry.LockedAt),
		WarningCodes:  sanitizeTemplateProvenanceWarningCodes(entry.WarningCodes),
		ReasonCode:    sanitizeTemplateProvenanceReasonCode(entry.ReasonCode),
	}
	if sanitized.Status == string(LockStatusLocked) {
		sanitized.DigestAlgorithm, sanitized.DigestValue = sanitizeTemplateProvenanceDigest(entry.DigestAlgorithm, entry.DigestValue)
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

func sanitizeTemplateProvenanceSourceKind(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(SourceKindLocalFile):
		return string(SourceKindLocalFile)
	case string(SourceKindOCIArtifact):
		return string(SourceKindOCIArtifact)
	case templateProvenanceSourceKindTemplateReference:
		return templateProvenanceSourceKindTemplateReference
	case templateProvenanceSourceKindRuntimeImage:
		return templateProvenanceSourceKindRuntimeImage
	case templateProvenanceSourceKindSourceArtifact:
		return templateProvenanceSourceKindSourceArtifact
	default:
		return ""
	}
}

func sanitizeTemplateProvenanceReferenceKind(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(sandboxtemplate.ReferenceKindLocal):
		return string(sandboxtemplate.ReferenceKindLocal)
	case string(sandboxtemplate.ReferenceKindOCIArtifact):
		return string(sandboxtemplate.ReferenceKindOCIArtifact)
	case string(sandboxtemplate.ReferenceKindOCIImage):
		return string(sandboxtemplate.ReferenceKindOCIImage)
	case string(sandboxtemplate.ReferenceKindGit):
		return string(sandboxtemplate.ReferenceKindGit)
	case string(sandboxtemplate.ReferenceKindInline):
		return string(sandboxtemplate.ReferenceKindInline)
	default:
		return ""
	}
}

func sanitizeTemplateProvenanceStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(LockStatusLocked):
		return string(LockStatusLocked)
	case string(LockStatusUnresolved):
		return string(LockStatusUnresolved)
	default:
		return ""
	}
}

func sanitizeTemplateProvenanceDigest(algorithm string, value string) (string, string) {
	digest := &sandboxtemplate.DigestMetadata{
		Algorithm: sandboxtemplate.DigestAlgorithm(strings.ToLower(strings.TrimSpace(algorithm))),
		Value:     strings.ToLower(strings.TrimSpace(value)),
	}
	if !sandboxtemplate.ReferenceDigestPinned(&sandboxtemplate.ImmutableRef{Digest: digest}) {
		return "", ""
	}
	return string(digest.Algorithm), digest.Value
}

func sanitizeTemplateProvenanceSizeBytes(value int64) int64 {
	if value <= 0 {
		return 0
	}
	return value
}

func sanitizeTemplateProvenanceTimestamp(value string) string {
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

func sanitizeTemplateProvenanceReasonCode(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if templateProvenanceAllowedReasonCode(normalized) {
		return normalized
	}
	return ""
}

func sanitizeTemplateProvenanceWarningCodes(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sanitized := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		code := sanitizeTemplateProvenanceReasonCode(value)
		if code == "" || seen[code] {
			continue
		}
		sanitized = append(sanitized, code)
		seen[code] = true
		if len(sanitized) == templateProvenanceMaxWarningCodes {
			break
		}
	}
	if len(sanitized) == 0 {
		return nil
	}
	return sanitized
}

func templateProvenanceAllowedReasonCode(code string) bool {
	switch LockReasonCode(code) {
	case LockReasonDocumentDigest,
		LockReasonTemplateReferenceDigest,
		LockReasonRuntimeImageDigest,
		LockReasonSourceArtifactDigest,
		LockReasonImmutableDigest,
		LockReasonMutableReference,
		LockReasonUnresolvedMutableReference,
		LockReasonResolverUnavailable,
		LockReasonUnsupportedSource:
		return true
	default:
		return false
	}
}
