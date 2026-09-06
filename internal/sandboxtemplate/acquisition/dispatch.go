package acquisition

import (
	"context"

	"github.com/jywlabs/hal/internal/sandboxtemplate"
)

func (r DispatchResolver) Resolve(ctx context.Context, request ResolveRequest) (ResolveResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return ResolveResult{Lock: unresolvedTemplateLockForSource(request.Source, LockReasonResolverUnavailable)}, &ResolveError{
			Code:    ResolveErrorCodeInvalidSource,
			Message: "template resolution was canceled",
			Err:     err,
		}
	}

	switch request.Source.Kind {
	case SourceKindLocalFile:
		resolver := r.local
		if resolver == nil {
			resolver = NewLocalResolver()
		}
		return resolver.Resolve(ctx, request)
	case SourceKindGit:
		if r.git == nil {
			return ResolveResult{Lock: unresolvedTemplateLockForSource(request.Source, LockReasonResolverUnavailable)}, resolverUnavailableError()
		}
		return r.git.Resolve(ctx, request)
	case SourceKindOCIArtifact:
		if r.oci == nil {
			return ResolveResult{Lock: unresolvedTemplateLockForSource(request.Source, LockReasonResolverUnavailable)}, resolverUnavailableError()
		}
		return r.oci.Resolve(ctx, request)
	default:
		return ResolveResult{Lock: unresolvedTemplateLockForSource(request.Source, LockReasonUnsupportedSource)}, unsupportedSourceError()
	}
}

func unresolvedTemplateLockForSource(source TemplateSource, reason LockReasonCode) TemplateLock {
	sourceKind := sanitizeTemplateSourceStatusSourceKind(source.Kind)
	if sourceKind == "" && reason == LockReasonUnsupportedSource {
		sourceKind = SourceKindUnsupported
	}
	referenceKind := templateSourceReferenceKind(source)
	lock := TemplateLock{
		SourceKind:    sourceKind,
		ReferenceKind: referenceKind,
		Status:        LockStatusUnresolved,
		Document: DigestLock{
			Status:     LockStatusUnresolved,
			ReasonCode: reason,
		},
	}
	if reason == LockReasonUnsupportedSource {
		lock.Warnings = []LockReasonCode{LockReasonUnsupportedSource}
	}
	if referenceLock, ok := unresolvedTemplateSourceReferenceLock(source); ok {
		lock.References = []ReferenceLock{referenceLock}
	}
	return lock
}

func templateSourceReferenceKind(source TemplateSource) sandboxtemplate.ReferenceKind {
	if source.Reference != nil {
		return sanitizeTemplateSourceStatusReferenceKind(source.Reference.Kind)
	}
	switch source.Kind {
	case SourceKindLocalFile:
		return sandboxtemplate.ReferenceKindLocal
	case SourceKindGit:
		return sandboxtemplate.ReferenceKindGit
	case SourceKindOCIArtifact:
		return sandboxtemplate.ReferenceKindOCIArtifact
	default:
		return ""
	}
}

func unresolvedTemplateSourceReferenceLock(source TemplateSource) (ReferenceLock, bool) {
	if source.Reference == nil {
		return ReferenceLock{}, false
	}
	kind := sanitizeTemplateSourceStatusReferenceKind(source.Reference.Kind)
	if kind == "" {
		kind = templateSourceReferenceKind(source)
	}
	if kind == "" || kind == sandboxtemplate.ReferenceKindLocal {
		return ReferenceLock{}, false
	}
	lock := ReferenceLock{
		Field:      "metadata.reference",
		Kind:       kind,
		Status:     LockStatusUnresolved,
		ReasonCode: LockReasonUnresolvedMutableReference,
	}
	if digest := cloneValidDigestMetadata(source.Reference.Digest); digest != nil {
		lock.Status = LockStatusLocked
		lock.Digest = digest
		lock.ReasonCode = LockReasonImmutableDigest
	}
	return lock, true
}
