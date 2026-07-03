package acquisition

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxtemplate"
)

func (LocalResolver) Resolve(ctx context.Context, request ResolveRequest) (ResolveResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return ResolveResult{}, &ResolveError{
			Code:    ResolveErrorCodeInvalidSource,
			Message: "template resolution was canceled",
			Err:     err,
		}
	}
	if request.Source.Kind != SourceKindLocalFile {
		return ResolveResult{}, unsupportedSourceError()
	}

	format, ok := localTemplateFormat(request.Source)
	if !ok {
		return ResolveResult{}, &ResolveError{
			Code:    ResolveErrorCodeInvalidSource,
			Message: "local template source is invalid",
			Err:     ErrInvalidSource,
		}
	}

	data, err := os.ReadFile(request.Source.LocalPath)
	if err != nil {
		return ResolveResult{}, &ResolveError{
			Code:    ResolveErrorCodeReadFailed,
			Message: "local template document is unreadable",
			Err:     ErrLocalTemplateReadFailed,
		}
	}

	template, err := sandboxtemplate.DecodeBytes(data, format, "local template")
	if err != nil {
		return ResolveResult{}, &ResolveError{
			Code:    ResolveErrorCodeDecodeFailed,
			Message: "local template document is malformed",
			Err:     ErrTemplateDecodeFailed,
		}
	}

	validation := sandboxtemplate.ValidateTemplate(template)
	if !validation.Valid || validation.Normalized == nil {
		return ResolveResult{}, &ResolveError{
			Code:    ResolveErrorCodeValidationFailed,
			Message: "local template document is invalid",
			Err:     ErrTemplateValidationFailed,
		}
	}

	sanitized := sandboxtemplate.SanitizeTemplate(*validation.Normalized)
	return ResolveResult{
		Template: sanitized,
		Lock:     localTemplateLock(data, sanitized, request.LockedAtUnixMillis),
	}, nil
}

func localTemplateFormat(source TemplateSource) (sandboxtemplate.Format, bool) {
	if strings.TrimSpace(source.LocalPath) == "" {
		return "", false
	}

	format := sandboxtemplate.Format(strings.ToLower(strings.TrimSpace(string(source.Format))))
	switch format {
	case sandboxtemplate.FormatJSON, sandboxtemplate.FormatYAML:
		return format, true
	case "":
	default:
		return "", false
	}

	switch strings.ToLower(filepath.Ext(source.LocalPath)) {
	case ".json":
		return sandboxtemplate.FormatJSON, true
	case ".yaml", ".yml":
		return sandboxtemplate.FormatYAML, true
	default:
		return "", false
	}
}

func localTemplateLock(data []byte, template sandboxtemplate.Template, lockedAtUnixMillis int64) TemplateLock {
	return TemplateLock{
		SourceKind:    SourceKindLocalFile,
		ReferenceKind: sandboxtemplate.ReferenceKindLocal,
		Status:        LockStatusLocked,
		Document: DigestLock{
			Status:             LockStatusLocked,
			Digest:             documentDigest(data),
			SizeBytes:          int64(len(data)),
			LockedAtUnixMillis: lockedAtUnixMillis,
			ReasonCode:         LockReasonDocumentDigest,
		},
		References: templateReferenceLocks(template),
	}
}

func documentDigest(data []byte) *sandboxtemplate.DigestMetadata {
	sum := sha256.Sum256(data)
	return &sandboxtemplate.DigestMetadata{
		Algorithm: sandboxtemplate.DigestAlgorithmSHA256,
		Value:     hex.EncodeToString(sum[:]),
	}
}

func templateReferenceLocks(template sandboxtemplate.Template) []ReferenceLock {
	refs := make([]ReferenceLock, 0, 5)
	refs = appendReferenceLock(refs, "metadata.reference", template.Metadata.Reference)
	if template.Runtime != nil {
		refs = appendReferenceLock(refs, "runtime.image", template.Runtime.Image)
		if template.Runtime.Launch != nil {
			refs = appendReferenceLock(refs, "runtime.launch.descriptorRef", template.Runtime.Launch.DescriptorRef)
		}
	}
	if template.Workspace != nil {
		refs = appendReferenceLock(refs, "workspace.ref", template.Workspace.Ref)
	}
	if template.Network != nil {
		refs = appendReferenceLock(refs, "network.policySnapshotReference", template.Network.PolicySnapshotReference)
	}
	if len(refs) == 0 {
		return nil
	}
	return refs
}

func appendReferenceLock(refs []ReferenceLock, field string, ref *sandboxtemplate.ImmutableRef) []ReferenceLock {
	if ref == nil {
		return refs
	}
	lock := ReferenceLock{
		Field: field,
		Kind:  ref.Kind,
	}
	if sandboxtemplate.ReferenceDigestPinned(ref) {
		lock.Status = LockStatusLocked
		lock.Digest = cloneDigestMetadata(ref.Digest)
		lock.ReasonCode = LockReasonImmutableDigest
	} else {
		lock.Status = LockStatusUnresolved
		lock.ReasonCode = LockReasonMutableReference
	}
	return append(refs, lock)
}

func cloneDigestMetadata(digest *sandboxtemplate.DigestMetadata) *sandboxtemplate.DigestMetadata {
	if digest == nil {
		return nil
	}
	out := *digest
	return &out
}

func unsupportedSourceError() *ResolveError {
	return &ResolveError{
		Code:    ResolveErrorCodeUnsupportedSource,
		Message: "template source kind is unsupported",
		Err:     ErrUnsupportedSource,
	}
}
