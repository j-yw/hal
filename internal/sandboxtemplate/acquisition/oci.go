package acquisition

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/jywlabs/hal/internal/sandboxtemplate"
)

var ErrOCIArtifactFixtureNotFound = errors.New("oci artifact fixture is not available")

// InMemoryOCIArtifactResolver resolves OCI-like references from caller-provided
// fixtures. It is intended for fake-safe tests and never contacts a registry.
type InMemoryOCIArtifactResolver struct {
	fixtures map[string]OCIArtifactResolveResult
	calls    []OCIArtifactResolveRequest
}

type FakeOCIArtifactResolver = InMemoryOCIArtifactResolver

func NewInMemoryOCIArtifactResolver(fixtures map[string]OCIArtifactResolveResult) *InMemoryOCIArtifactResolver {
	resolver := &InMemoryOCIArtifactResolver{
		fixtures: make(map[string]OCIArtifactResolveResult, len(fixtures)),
	}
	for ref, result := range fixtures {
		resolver.fixtures[ref] = cloneOCIArtifactResolveResult(result)
	}
	return resolver
}

func NewFakeOCIArtifactResolver(fixtures map[string]OCIArtifactResolveResult) *InMemoryOCIArtifactResolver {
	return NewInMemoryOCIArtifactResolver(fixtures)
}

func (r *InMemoryOCIArtifactResolver) ResolveOCIArtifact(_ context.Context, request OCIArtifactResolveRequest) (OCIArtifactResolveResult, error) {
	if r == nil {
		return OCIArtifactResolveResult{}, ErrResolverUnavailable
	}
	r.calls = append(r.calls, cloneOCIArtifactResolveRequest(request))
	result, ok := r.fixtures[request.Reference.Ref]
	if !ok {
		return OCIArtifactResolveResult{}, ErrOCIArtifactFixtureNotFound
	}
	return cloneOCIArtifactResolveResult(result), nil
}

func (r *InMemoryOCIArtifactResolver) Calls() []OCIArtifactResolveRequest {
	if r == nil || len(r.calls) == 0 {
		return nil
	}
	out := make([]OCIArtifactResolveRequest, 0, len(r.calls))
	for _, call := range r.calls {
		out = append(out, cloneOCIArtifactResolveRequest(call))
	}
	return out
}

func (r OCIResolver) Resolve(ctx context.Context, request ResolveRequest) (ResolveResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return ResolveResult{}, canceledResolutionError(err)
	}
	if request.Source.Kind != SourceKindOCIArtifact {
		return ResolveResult{}, unsupportedSourceError()
	}
	if request.Source.Reference == nil || request.Source.Reference.Ref == "" || (request.Source.Reference.Kind != "" && request.Source.Reference.Kind != sandboxtemplate.ReferenceKindOCIArtifact) {
		return ResolveResult{}, &ResolveError{
			Code:    ResolveErrorCodeInvalidSource,
			Message: "oci template source is invalid",
			Err:     ErrInvalidSource,
		}
	}
	if r.artifactResolver == nil {
		return ResolveResult{}, resolverUnavailableError()
	}

	artifact, err := r.artifactResolver.ResolveOCIArtifact(ctx, OCIArtifactResolveRequest{
		Reference: normalizedOCIArtifactSourceReference(*request.Source.Reference),
	})
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ResolveResult{}, canceledResolutionError(ctxErr)
		}
		if code, ok := safeOCIArtifactResolveErrorCode(err); ok {
			return ResolveResult{}, &ResolveError{Code: code, Err: err}
		}
		return ResolveResult{}, resolverUnavailableError()
	}
	if err := ctx.Err(); err != nil {
		return ResolveResult{}, canceledResolutionError(err)
	}
	if err := verifyOCIArtifactMeasuredEvidence(artifact); err != nil {
		return ResolveResult{}, err
	}

	format := artifact.Format
	if format == "" {
		format = request.Source.Format
	}
	template, err := sandboxtemplate.DecodeBytes(artifact.TemplateBytes, format, "oci template artifact")
	if err != nil {
		return ResolveResult{}, &ResolveError{
			Code:    ResolveErrorCodeDecodeFailed,
			Message: "oci template document is malformed",
			Err:     ErrTemplateDecodeFailed,
		}
	}

	validation := sandboxtemplate.ValidateTemplate(template)
	if !validation.Valid || validation.Normalized == nil {
		return ResolveResult{}, &ResolveError{
			Code:    ResolveErrorCodeValidationFailed,
			Message: "oci template document is invalid",
			Err:     ErrTemplateValidationFailed,
		}
	}

	sanitized := sandboxtemplate.SanitizeTemplate(*validation.Normalized)
	if err := ctx.Err(); err != nil {
		return ResolveResult{}, canceledResolutionError(err)
	}
	return ResolveResult{
		Template: sanitized,
		Lock:     ociTemplateLock(artifact, sanitized, request.LockedAtUnixMillis),
	}, nil
}

type safeOCIArtifactResolveError interface {
	SafeCode() string
}

func safeOCIArtifactResolveErrorCode(err error) (ResolveErrorCode, bool) {
	var coded safeOCIArtifactResolveError
	if !errors.As(err, &coded) {
		return "", false
	}
	code := ResolveErrorCode(coded.SafeCode())
	switch code {
	case "invalid_reference",
		"request_canceled",
		"request_timeout",
		"registry_unavailable",
		"address_rejected",
		"authentication_failed",
		"authentication_challenge_invalid",
		"authentication_response_oversize",
		"response_headers_oversize",
		"response_headers_invalid",
		"redirect_rejected",
		"manifest_oversize",
		"manifest_media_type_unsupported",
		"manifest_invalid",
		"manifest_digest_mismatch",
		"tag_mutated",
		"artifact_type_unsupported",
		"layer_count_invalid",
		"layer_media_type_unsupported",
		"layer_oversize",
		"layer_digest_mismatch",
		"cache_invalid",
		"cache_publish_failed":
		return code, true
	default:
		return "", false
	}
}

func canceledResolutionError(err error) *ResolveError {
	code := ResolveErrorCodeRequestCanceled
	if errors.Is(err, context.DeadlineExceeded) {
		code = ResolveErrorCodeRequestTimeout
	}
	return &ResolveError{
		Code: code,
		Err:  err,
	}
}

func resolverUnavailableError() *ResolveError {
	return &ResolveError{
		Code:    ResolveErrorCodeResolverUnavailable,
		Message: "template acquisition resolver is unavailable",
		Err:     ErrResolverUnavailable,
	}
}

func ociTemplateLock(artifact OCIArtifactResolveResult, template sandboxtemplate.Template, lockedAtUnixMillis int64) TemplateLock {
	return TemplateLock{
		SourceKind:    SourceKindOCIArtifact,
		ReferenceKind: sandboxtemplate.ReferenceKindOCIArtifact,
		Status:        LockStatusLocked,
		Document:      ociDocumentLock(artifact, lockedAtUnixMillis),
		References:    ociTemplateReferenceLocks(template, artifact),
	}
}

func ociDocumentLock(artifact OCIArtifactResolveResult, lockedAtUnixMillis int64) DigestLock {
	digest := cloneValidDigestMetadata(artifact.DocumentDigest)
	reason := LockReasonImmutableDigest
	if digest == nil {
		digest = documentDigest(artifact.TemplateBytes)
		reason = LockReasonDocumentDigest
	}
	sizeBytes := artifact.SizeBytes
	if sizeBytes <= 0 {
		sizeBytes = int64(len(artifact.TemplateBytes))
	}
	return DigestLock{
		Status:             LockStatusLocked,
		Digest:             digest,
		SizeBytes:          sizeBytes,
		LockedAtUnixMillis: lockedAtUnixMillis,
		ReasonCode:         reason,
	}
}

func ociTemplateReferenceLocks(template sandboxtemplate.Template, artifact OCIArtifactResolveResult) []ReferenceLock {
	refs := make([]ReferenceLock, 0, 5)
	artifactDigest := cloneValidDigestMetadata(artifact.TemplateArtifactDigest)
	refs = appendOCIReferenceLock(refs, "metadata.reference", template.Metadata.Reference, artifact.ReferenceDigests, artifactDigest)
	refs = appendMissingTemplateArtifactLock(refs, template.Metadata.Reference, artifactDigest)
	if template.Runtime != nil {
		refs = appendOCIReferenceLock(refs, "runtime.image", template.Runtime.Image, artifact.ReferenceDigests, nil)
		if template.Runtime.Launch != nil {
			refs = appendOCIReferenceLock(refs, "runtime.launch.descriptorRef", template.Runtime.Launch.DescriptorRef, artifact.ReferenceDigests, nil)
		}
	}
	if template.Workspace != nil {
		refs = appendOCIReferenceLock(refs, "workspace.ref", template.Workspace.Ref, artifact.ReferenceDigests, nil)
	}
	if template.Network != nil {
		refs = appendOCIReferenceLock(refs, "network.policySnapshotReference", template.Network.PolicySnapshotReference, artifact.ReferenceDigests, nil)
	}
	if len(refs) == 0 {
		return nil
	}
	return refs
}

func appendMissingTemplateArtifactLock(refs []ReferenceLock, metadataReference *sandboxtemplate.ImmutableRef, artifactDigest *sandboxtemplate.DigestMetadata) []ReferenceLock {
	if metadataReference != nil || artifactDigest == nil {
		return refs
	}
	return append(refs, ReferenceLock{
		Field:      "metadata.reference",
		Kind:       sandboxtemplate.ReferenceKindOCIArtifact,
		Status:     LockStatusLocked,
		Digest:     cloneDigestMetadata(artifactDigest),
		ReasonCode: LockReasonImmutableDigest,
	})
}

func appendOCIReferenceLock(refs []ReferenceLock, field string, ref *sandboxtemplate.ImmutableRef, proofs []ReferenceDigestProof, preferredDigest *sandboxtemplate.DigestMetadata) []ReferenceLock {
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

func matchingProofDigest(field string, ref *sandboxtemplate.ImmutableRef, proofs []ReferenceDigestProof) *sandboxtemplate.DigestMetadata {
	for _, proof := range proofs {
		if proof.Field != field {
			continue
		}
		if proof.Kind != "" && proof.Kind != ref.Kind {
			continue
		}
		if proof.Ref != "" && proof.Ref != ref.Ref {
			continue
		}
		if digest := cloneValidDigestMetadata(proof.Digest); digest != nil {
			return digest
		}
	}
	return nil
}

func cloneValidDigestMetadata(digest *sandboxtemplate.DigestMetadata) *sandboxtemplate.DigestMetadata {
	out := cloneDigestMetadata(digest)
	if out == nil {
		return nil
	}
	if !sandboxtemplate.ReferenceDigestPinned(&sandboxtemplate.ImmutableRef{Digest: out}) {
		return nil
	}
	return out
}

func cloneOCIArtifactResolveRequest(request OCIArtifactResolveRequest) OCIArtifactResolveRequest {
	return OCIArtifactResolveRequest{
		Reference: cloneImmutableRefValue(request.Reference),
	}
}

func cloneOCIArtifactResolveResult(result OCIArtifactResolveResult) OCIArtifactResolveResult {
	out := OCIArtifactResolveResult{
		TemplateBytes:          append([]byte(nil), result.TemplateBytes...),
		ArtifactManifestBytes:  append([]byte(nil), result.ArtifactManifestBytes...),
		Format:                 result.Format,
		DocumentDigest:         cloneDigestMetadata(result.DocumentDigest),
		TemplateArtifactDigest: cloneDigestMetadata(result.TemplateArtifactDigest),
		SizeBytes:              result.SizeBytes,
	}
	if len(result.ReferenceDigests) > 0 {
		out.ReferenceDigests = make([]ReferenceDigestProof, 0, len(result.ReferenceDigests))
		for _, proof := range result.ReferenceDigests {
			out.ReferenceDigests = append(out.ReferenceDigests, ReferenceDigestProof{
				Field:         proof.Field,
				Kind:          proof.Kind,
				Ref:           proof.Ref,
				Digest:        cloneDigestMetadata(proof.Digest),
				VerifiedBytes: append([]byte(nil), proof.VerifiedBytes...),
			})
		}
	}
	return out
}

func verifyOCIArtifactMeasuredEvidence(artifact OCIArtifactResolveResult) error {
	if artifact.SizeBytes > 0 && artifact.SizeBytes != int64(len(artifact.TemplateBytes)) {
		return ociDigestMismatchError()
	}
	if artifact.DocumentDigest != nil && !digestMatchesBytes(artifact.DocumentDigest, artifact.TemplateBytes) {
		return ociDigestMismatchError()
	}
	if artifact.TemplateArtifactDigest != nil &&
		(len(artifact.ArtifactManifestBytes) == 0 || !digestMatchesBytes(artifact.TemplateArtifactDigest, artifact.ArtifactManifestBytes)) {
		return ociDigestMismatchError()
	}
	for _, proof := range artifact.ReferenceDigests {
		if proof.Digest == nil {
			continue
		}
		if len(proof.VerifiedBytes) == 0 || !digestMatchesBytes(proof.Digest, proof.VerifiedBytes) {
			return ociDigestMismatchError()
		}
	}
	return nil
}

func digestMatchesBytes(digest *sandboxtemplate.DigestMetadata, data []byte) bool {
	if digest == nil || digest.Algorithm != sandboxtemplate.DigestAlgorithmSHA256 || len(digest.Value) != 64 {
		return false
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]) == digest.Value
}

func ociDigestMismatchError() *ResolveError {
	return &ResolveError{
		Code:    ResolveErrorCodeDigestMismatch,
		Message: "oci template digest evidence does not match verified bytes",
		Err:     ErrInvalidSource,
	}
}

func cloneImmutableRefValue(ref sandboxtemplate.ImmutableRef) sandboxtemplate.ImmutableRef {
	return sandboxtemplate.ImmutableRef{
		Kind:   ref.Kind,
		Ref:    ref.Ref,
		Digest: cloneDigestMetadata(ref.Digest),
	}
}

func normalizedOCIArtifactSourceReference(ref sandboxtemplate.ImmutableRef) sandboxtemplate.ImmutableRef {
	out := cloneImmutableRefValue(ref)
	if out.Kind == "" {
		out.Kind = sandboxtemplate.ReferenceKindOCIArtifact
	}
	return out
}
