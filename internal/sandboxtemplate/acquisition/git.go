package acquisition

import (
	"context"
	"errors"

	"github.com/jywlabs/hal/internal/sandboxtemplate"
)

var ErrGitTemplateFixtureNotFound = errors.New("git template fixture is not available")

// InMemoryGitTemplateResolver resolves Git template references from
// caller-provided fixtures. It is intended for fake-safe tests.
type InMemoryGitTemplateResolver struct {
	fixtures map[string]GitTemplateResolveResult
	calls    []GitTemplateResolveRequest
}

type FakeGitTemplateResolver = InMemoryGitTemplateResolver

func NewInMemoryGitTemplateResolver(fixtures map[string]GitTemplateResolveResult) *InMemoryGitTemplateResolver {
	resolver := &InMemoryGitTemplateResolver{
		fixtures: make(map[string]GitTemplateResolveResult, len(fixtures)),
	}
	for ref, result := range fixtures {
		resolver.fixtures[ref] = cloneGitTemplateResolveResult(result)
	}
	return resolver
}

func NewFakeGitTemplateResolver(fixtures map[string]GitTemplateResolveResult) *InMemoryGitTemplateResolver {
	return NewInMemoryGitTemplateResolver(fixtures)
}

func (r *InMemoryGitTemplateResolver) ResolveGitTemplate(_ context.Context, request GitTemplateResolveRequest) (GitTemplateResolveResult, error) {
	if r == nil {
		return GitTemplateResolveResult{}, ErrResolverUnavailable
	}
	r.calls = append(r.calls, cloneGitTemplateResolveRequest(request))
	result, ok := r.fixtures[request.Reference.Ref]
	if !ok {
		return GitTemplateResolveResult{}, ErrGitTemplateFixtureNotFound
	}
	return cloneGitTemplateResolveResult(result), nil
}

func (r *InMemoryGitTemplateResolver) Calls() []GitTemplateResolveRequest {
	if r == nil || len(r.calls) == 0 {
		return nil
	}
	out := make([]GitTemplateResolveRequest, 0, len(r.calls))
	for _, call := range r.calls {
		out = append(out, cloneGitTemplateResolveRequest(call))
	}
	return out
}

func (r GitResolver) Resolve(ctx context.Context, request ResolveRequest) (ResolveResult, error) {
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
	if request.Source.Kind != SourceKindGit {
		return ResolveResult{}, unsupportedSourceError()
	}
	if request.Source.Reference == nil || request.Source.Reference.Ref == "" || (request.Source.Reference.Kind != "" && request.Source.Reference.Kind != sandboxtemplate.ReferenceKindGit) {
		return ResolveResult{}, &ResolveError{
			Code:    ResolveErrorCodeInvalidSource,
			Message: "git template source is invalid",
			Err:     ErrInvalidSource,
		}
	}
	if r.templateResolver == nil {
		return ResolveResult{}, resolverUnavailableError()
	}

	resolved, err := r.templateResolver.ResolveGitTemplate(ctx, GitTemplateResolveRequest{
		Reference: normalizedGitTemplateSourceReference(*request.Source.Reference),
	})
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ResolveResult{}, &ResolveError{
				Code:    ResolveErrorCodeInvalidSource,
				Message: "template resolution was canceled",
				Err:     ctxErr,
			}
		}
		return ResolveResult{}, resolverUnavailableError()
	}

	format := resolved.Format
	if format == "" {
		format = request.Source.Format
	}
	template, err := sandboxtemplate.DecodeBytes(resolved.TemplateBytes, format, "git template document")
	if err != nil {
		return ResolveResult{}, &ResolveError{
			Code:    ResolveErrorCodeDecodeFailed,
			Message: "git template document is malformed",
			Err:     ErrTemplateDecodeFailed,
		}
	}

	validation := sandboxtemplate.ValidateTemplate(template)
	if !validation.Valid || validation.Normalized == nil {
		return ResolveResult{}, &ResolveError{
			Code:    ResolveErrorCodeValidationFailed,
			Message: "git template document is invalid",
			Err:     ErrTemplateValidationFailed,
		}
	}

	sanitized := sandboxtemplate.SanitizeTemplate(*validation.Normalized)
	return ResolveResult{
		Template: sanitized,
		Lock:     gitTemplateLock(resolved, sanitized, request.Source.Reference, request.LockedAtUnixMillis),
	}, nil
}

func gitTemplateLock(resolved GitTemplateResolveResult, template sandboxtemplate.Template, sourceRef *sandboxtemplate.ImmutableRef, lockedAtUnixMillis int64) TemplateLock {
	return TemplateLock{
		SourceKind:    SourceKindGit,
		ReferenceKind: sandboxtemplate.ReferenceKindGit,
		Status:        LockStatusLocked,
		Document:      gitDocumentLock(resolved, lockedAtUnixMillis),
		References:    gitTemplateReferenceLocks(template, sourceRef, resolved),
	}
}

func gitDocumentLock(resolved GitTemplateResolveResult, lockedAtUnixMillis int64) DigestLock {
	digest := cloneValidDigestMetadata(resolved.DocumentDigest)
	reason := LockReasonImmutableDigest
	if digest == nil {
		digest = documentDigest(resolved.TemplateBytes)
		reason = LockReasonDocumentDigest
	}
	sizeBytes := resolved.SizeBytes
	if sizeBytes <= 0 {
		sizeBytes = int64(len(resolved.TemplateBytes))
	}
	return DigestLock{
		Status:             LockStatusLocked,
		Digest:             digest,
		SizeBytes:          sizeBytes,
		LockedAtUnixMillis: lockedAtUnixMillis,
		ReasonCode:         reason,
	}
}

func gitTemplateReferenceLocks(template sandboxtemplate.Template, sourceRef *sandboxtemplate.ImmutableRef, resolved GitTemplateResolveResult) []ReferenceLock {
	refs := make([]ReferenceLock, 0, 5)
	sourceDigest := cloneValidDigestMetadata(resolved.SourceDigest)
	refs = appendGitReferenceLock(refs, "metadata.reference", template.Metadata.Reference, resolved.ReferenceDigests, sourceDigest)
	refs = appendMissingGitSourceReferenceLock(refs, template.Metadata.Reference, sourceRef, sourceDigest)
	if template.Runtime != nil {
		refs = appendGitReferenceLock(refs, "runtime.image", template.Runtime.Image, resolved.ReferenceDigests, nil)
		if template.Runtime.Launch != nil {
			refs = appendGitReferenceLock(refs, "runtime.launch.descriptorRef", template.Runtime.Launch.DescriptorRef, resolved.ReferenceDigests, nil)
		}
	}
	if template.Workspace != nil {
		refs = appendGitReferenceLock(refs, "workspace.ref", template.Workspace.Ref, resolved.ReferenceDigests, nil)
	}
	if template.Network != nil {
		refs = appendGitReferenceLock(refs, "network.policySnapshotReference", template.Network.PolicySnapshotReference, resolved.ReferenceDigests, nil)
	}
	if len(refs) == 0 {
		return nil
	}
	return refs
}

func appendMissingGitSourceReferenceLock(refs []ReferenceLock, metadataReference *sandboxtemplate.ImmutableRef, sourceRef *sandboxtemplate.ImmutableRef, sourceDigest *sandboxtemplate.DigestMetadata) []ReferenceLock {
	if metadataReference != nil || sourceRef == nil {
		return refs
	}
	return appendGitReferenceLock(refs, "metadata.reference", sourceRef, nil, sourceDigest)
}

func appendGitReferenceLock(refs []ReferenceLock, field string, ref *sandboxtemplate.ImmutableRef, proofs []ReferenceDigestProof, preferredDigest *sandboxtemplate.DigestMetadata) []ReferenceLock {
	if ref == nil {
		return refs
	}
	lock := ReferenceLock{
		Field: field,
		Kind:  ref.Kind,
	}
	if preferredDigest != nil {
		lock.Status = LockStatusLocked
		lock.Digest = cloneDigestMetadata(preferredDigest)
		lock.ReasonCode = LockReasonImmutableDigest
		return append(refs, lock)
	}
	if proofDigest := matchingProofDigest(field, ref, proofs); proofDigest != nil {
		lock.Status = LockStatusLocked
		lock.Digest = proofDigest
		lock.ReasonCode = LockReasonImmutableDigest
		return append(refs, lock)
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

func cloneGitTemplateResolveRequest(request GitTemplateResolveRequest) GitTemplateResolveRequest {
	return GitTemplateResolveRequest{
		Reference: cloneImmutableRefValue(request.Reference),
	}
}

func cloneGitTemplateResolveResult(result GitTemplateResolveResult) GitTemplateResolveResult {
	out := GitTemplateResolveResult{
		TemplateBytes:  append([]byte(nil), result.TemplateBytes...),
		Format:         result.Format,
		DocumentDigest: cloneDigestMetadata(result.DocumentDigest),
		SourceDigest:   cloneDigestMetadata(result.SourceDigest),
		SizeBytes:      result.SizeBytes,
	}
	if len(result.ReferenceDigests) > 0 {
		out.ReferenceDigests = make([]ReferenceDigestProof, 0, len(result.ReferenceDigests))
		for _, proof := range result.ReferenceDigests {
			out.ReferenceDigests = append(out.ReferenceDigests, ReferenceDigestProof{
				Field:  proof.Field,
				Kind:   proof.Kind,
				Ref:    proof.Ref,
				Digest: cloneDigestMetadata(proof.Digest),
			})
		}
	}
	return out
}

func normalizedGitTemplateSourceReference(ref sandboxtemplate.ImmutableRef) sandboxtemplate.ImmutableRef {
	out := cloneImmutableRefValue(ref)
	if out.Kind == "" {
		out.Kind = sandboxtemplate.ReferenceKindGit
	}
	return out
}
