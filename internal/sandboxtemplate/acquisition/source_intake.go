package acquisition

import (
	"encoding/json"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxtemplate"
)

const (
	SourceKindGit         SourceKind = "git"
	SourceKindUnsupported SourceKind = "unsupported"
)

// TemplateSourceClassification is the intake boundary between raw operator
// input and later acquisition. Source can retain caller input for resolvers;
// Status and Lock are the redaction-safe public metadata surfaces.
type TemplateSourceClassification struct {
	Source TemplateSource       `json:"-"`
	Status TemplateSourceStatus `json:"status,omitempty"`
	Lock   TemplateLock         `json:"lock,omitempty"`
}

// TemplateSourceStatus is public, redaction-safe source classification
// metadata. It intentionally omits raw local paths, URLs, query strings, and
// auth material.
type TemplateSourceStatus struct {
	SourceKind    SourceKind                      `json:"sourceKind,omitempty"`
	ReferenceKind sandboxtemplate.ReferenceKind   `json:"referenceKind,omitempty"`
	Status        LockStatus                      `json:"status,omitempty"`
	Digest        *sandboxtemplate.DigestMetadata `json:"digest,omitempty"`
	ReasonCode    LockReasonCode                  `json:"reasonCode,omitempty"`
	WarningCodes  []LockReasonCode                `json:"warningCodes,omitempty"`
}

// ClassifyTemplateSourceReference maps a caller-supplied template reference
// into resolver input plus redaction-safe status and lock metadata without
// reading local files or contacting remote services.
func ClassifyTemplateSourceReference(input string, format sandboxtemplate.Format) TemplateSourceClassification {
	reference := sandboxtemplate.ClassifyTemplateReference(input)
	sourceKind := templateSourceKindForReference(reference)
	source := TemplateSource{
		Kind:   sourceKind,
		Format: format,
	}
	if reference.Status == sandboxtemplate.TemplateReferenceStatusAccepted {
		switch sourceKind {
		case SourceKindLocalFile:
			source.LocalPath = strings.TrimSpace(input)
		case SourceKindGit, SourceKindOCIArtifact:
			source.Reference = cloneIntakeImmutableRef(reference.Reference)
		}
	}

	status := templateSourceStatusFromReference(sourceKind, reference)
	return TemplateSourceClassification{
		Source: source,
		Status: status,
		Lock:   templateSourceClassificationLock(status),
	}
}

func (status TemplateSourceStatus) MarshalJSON() ([]byte, error) {
	type templateSourceStatusJSON TemplateSourceStatus
	sanitized := SanitizeTemplateSourceStatus(status)
	return json.Marshal(templateSourceStatusJSON(sanitized))
}

func (status *TemplateSourceStatus) UnmarshalJSON(data []byte) error {
	type templateSourceStatusJSON TemplateSourceStatus
	var decoded templateSourceStatusJSON
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*status = SanitizeTemplateSourceStatus(TemplateSourceStatus(decoded))
	return nil
}

// SanitizeTemplateSourceStatus returns a redaction-safe source status copy.
func SanitizeTemplateSourceStatus(status TemplateSourceStatus) TemplateSourceStatus {
	out := TemplateSourceStatus{
		SourceKind:    sanitizeTemplateSourceStatusSourceKind(status.SourceKind),
		ReferenceKind: sanitizeTemplateSourceStatusReferenceKind(status.ReferenceKind),
		Status:        sanitizeTemplateSourceStatusLockStatus(status.Status),
		Digest:        cloneValidDigestMetadata(status.Digest),
		ReasonCode:    sanitizeTemplateSourceStatusReasonCode(status.ReasonCode),
		WarningCodes:  sanitizeTemplateSourceStatusWarningCodes(status.WarningCodes),
	}
	if out.Status != LockStatusUnresolved {
		out.Digest = nil
	}
	return out
}

func templateSourceKindForReference(reference sandboxtemplate.TemplateReferenceClassification) SourceKind {
	if reference.Status != sandboxtemplate.TemplateReferenceStatusAccepted {
		return SourceKindUnsupported
	}
	switch reference.Kind {
	case sandboxtemplate.ReferenceKindLocal:
		return SourceKindLocalFile
	case sandboxtemplate.ReferenceKindGit:
		return SourceKindGit
	case sandboxtemplate.ReferenceKindOCIArtifact:
		return SourceKindOCIArtifact
	default:
		return SourceKindUnsupported
	}
}

func templateSourceStatusFromReference(sourceKind SourceKind, reference sandboxtemplate.TemplateReferenceClassification) TemplateSourceStatus {
	status := TemplateSourceStatus{
		SourceKind: sourceKind,
		Status:     LockStatusUnresolved,
		ReasonCode: LockReasonUnsupportedSource,
	}
	if reference.Status == sandboxtemplate.TemplateReferenceStatusAccepted && reference.Reference != nil {
		status.ReferenceKind = reference.Reference.Kind
		if reference.DigestPinned {
			status.Digest = cloneDigestMetadata(reference.Reference.Digest)
			status.ReasonCode = LockReasonImmutableDigest
		} else {
			status.ReasonCode = LockReasonUnresolvedMutableReference
		}
	} else {
		status.WarningCodes = []LockReasonCode{LockReasonUnsupportedSource}
	}
	return SanitizeTemplateSourceStatus(status)
}

func templateSourceClassificationLock(status TemplateSourceStatus) TemplateLock {
	lock := TemplateLock{
		SourceKind:    status.SourceKind,
		ReferenceKind: status.ReferenceKind,
		Status:        LockStatusUnresolved,
		Document: DigestLock{
			Status:     LockStatusUnresolved,
			ReasonCode: LockReasonResolverUnavailable,
		},
		Warnings: cloneLockReasonCodes(status.WarningCodes),
	}
	if status.SourceKind == SourceKindUnsupported {
		lock.Document.ReasonCode = LockReasonUnsupportedSource
		return lock
	}
	if status.ReferenceKind == "" || status.ReferenceKind == sandboxtemplate.ReferenceKindLocal {
		return lock
	}

	referenceLock := ReferenceLock{
		Field:      "metadata.reference",
		Kind:       status.ReferenceKind,
		Status:     LockStatusUnresolved,
		ReasonCode: LockReasonUnresolvedMutableReference,
	}
	if status.Digest != nil {
		referenceLock.Status = LockStatusLocked
		referenceLock.Digest = cloneDigestMetadata(status.Digest)
		referenceLock.ReasonCode = LockReasonImmutableDigest
	}
	lock.References = []ReferenceLock{referenceLock}
	return lock
}

func sanitizeTemplateSourceStatusSourceKind(kind SourceKind) SourceKind {
	switch kind {
	case SourceKindLocalFile, SourceKindGit, SourceKindOCIArtifact, SourceKindUnsupported:
		return kind
	default:
		return ""
	}
}

func sanitizeTemplateSourceStatusReferenceKind(kind sandboxtemplate.ReferenceKind) sandboxtemplate.ReferenceKind {
	switch kind {
	case sandboxtemplate.ReferenceKindLocal,
		sandboxtemplate.ReferenceKindGit,
		sandboxtemplate.ReferenceKindOCIArtifact:
		return kind
	default:
		return ""
	}
}

func sanitizeTemplateSourceStatusLockStatus(status LockStatus) LockStatus {
	switch status {
	case LockStatusLocked, LockStatusUnresolved:
		return status
	default:
		return ""
	}
}

func sanitizeTemplateSourceStatusReasonCode(code LockReasonCode) LockReasonCode {
	if templateProvenanceAllowedReasonCode(string(code)) {
		return code
	}
	return ""
}

func sanitizeTemplateSourceStatusWarningCodes(codes []LockReasonCode) []LockReasonCode {
	if len(codes) == 0 {
		return nil
	}
	out := make([]LockReasonCode, 0, len(codes))
	seen := map[LockReasonCode]bool{}
	for _, code := range codes {
		clean := sanitizeTemplateSourceStatusReasonCode(code)
		if clean == "" || seen[clean] {
			continue
		}
		out = append(out, clean)
		seen[clean] = true
		if len(out) == templateProvenanceMaxWarningCodes {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func cloneIntakeImmutableRef(ref *sandboxtemplate.ImmutableRef) *sandboxtemplate.ImmutableRef {
	if ref == nil {
		return nil
	}
	return &sandboxtemplate.ImmutableRef{
		Kind:   ref.Kind,
		Ref:    ref.Ref,
		Digest: cloneDigestMetadata(ref.Digest),
	}
}

func cloneLockReasonCodes(codes []LockReasonCode) []LockReasonCode {
	if len(codes) == 0 {
		return nil
	}
	out := make([]LockReasonCode, len(codes))
	copy(out, codes)
	return out
}
