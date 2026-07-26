// Package acquisition defines sandbox template acquisition contracts.
package acquisition

import (
	"context"
	"errors"

	"github.com/jywlabs/hal/internal/sandboxtemplate"
)

const (
	SourceKindLocalFile   SourceKind = "local_file"
	SourceKindOCIArtifact SourceKind = "oci_artifact"
)

const (
	LockStatusLocked     LockStatus = "locked"
	LockStatusUnresolved LockStatus = "unresolved"
)

const (
	LockReasonMutableReference           LockReasonCode = "mutable_reference"
	LockReasonImmutableDigest            LockReasonCode = "immutable_digest"
	LockReasonDocumentDigest             LockReasonCode = "document_digest"
	LockReasonTemplateReferenceDigest    LockReasonCode = "template_reference_digest"
	LockReasonRuntimeImageDigest         LockReasonCode = "runtime_image_digest"
	LockReasonSourceArtifactDigest       LockReasonCode = "source_artifact_digest"
	LockReasonUnresolvedMutableReference LockReasonCode = "unresolved_mutable_reference"
	LockReasonResolverUnavailable        LockReasonCode = "resolver_unavailable"
	LockReasonUnsupportedSource          LockReasonCode = "unsupported_source"
)

var ErrResolverUnavailable = errors.New("sandbox template acquisition resolver is unavailable")
var ErrUnsupportedSource = errors.New("sandbox template acquisition source kind is unsupported")

type SourceKind string
type LockStatus string
type LockReasonCode string
type ResolveErrorCode string

const (
	ResolveErrorCodeResolverUnavailable ResolveErrorCode = "resolver_unavailable"
	ResolveErrorCodeUnsupportedSource   ResolveErrorCode = "unsupported_source"
	ResolveErrorCodeInvalidSource       ResolveErrorCode = "invalid_source"
	ResolveErrorCodeReadFailed          ResolveErrorCode = "read_failed"
	ResolveErrorCodeDecodeFailed        ResolveErrorCode = "decode_failed"
	ResolveErrorCodeValidationFailed    ResolveErrorCode = "validation_failed"
	ResolveErrorCodeDigestMismatch      ResolveErrorCode = "digest_mismatch"
)

var ErrInvalidSource = errors.New("sandbox template acquisition source is invalid")
var ErrLocalTemplateReadFailed = errors.New("local template document read failed")
var ErrTemplateDecodeFailed = errors.New("sandbox template document decode failed")
var ErrTemplateValidationFailed = errors.New("sandbox template document validation failed")

// ResolveError carries stable, redaction-safe acquisition failure metadata.
type ResolveError struct {
	Code    ResolveErrorCode `json:"code"`
	Message string           `json:"message,omitempty"`
	Err     error            `json:"-"`
}

func (e *ResolveError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message == "" {
		return string(e.Code)
	}
	return string(e.Code) + ": " + e.Message
}

func (e *ResolveError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// ResolveRequest describes one sandbox template acquisition request.
type ResolveRequest struct {
	Source             TemplateSource `json:"source"`
	LockedAtUnixMillis int64          `json:"lockedAtUnixMillis,omitempty"`
}

// TemplateSource describes the requested template source without durable
// persistence requirements. LocalPath is caller input and must not be copied
// into persisted lock metadata.
type TemplateSource struct {
	Kind      SourceKind                    `json:"kind"`
	LocalPath string                        `json:"localPath,omitempty"`
	Reference *sandboxtemplate.ImmutableRef `json:"reference,omitempty"`
	Format    sandboxtemplate.Format        `json:"format,omitempty"`
}

// ResolveResult is the resolved template plus redaction-safe acquisition lock
// metadata.
type ResolveResult struct {
	Template sandboxtemplate.Template `json:"template"`
	Lock     TemplateLock             `json:"lock"`
}

// Resolver resolves a sandbox template source into normalized template
// metadata and redaction-safe acquisition lock metadata.
type Resolver interface {
	Resolve(context.Context, ResolveRequest) (ResolveResult, error)
}

// TemplateLock records the immutable identity proven during acquisition.
type TemplateLock struct {
	SourceKind    SourceKind                    `json:"sourceKind,omitempty"`
	ReferenceKind sandboxtemplate.ReferenceKind `json:"referenceKind,omitempty"`
	Status        LockStatus                    `json:"status,omitempty"`
	Document      DigestLock                    `json:"document,omitempty"`
	References    []ReferenceLock               `json:"references,omitempty"`
	Warnings      []LockReasonCode              `json:"warnings,omitempty"`
}

// DigestLock records a digest lock without retaining source-local paths.
type DigestLock struct {
	Status             LockStatus                      `json:"status,omitempty"`
	Digest             *sandboxtemplate.DigestMetadata `json:"digest,omitempty"`
	SizeBytes          int64                           `json:"sizeBytes,omitempty"`
	LockedAtUnixMillis int64                           `json:"lockedAtUnixMillis,omitempty"`
	ReasonCode         LockReasonCode                  `json:"reasonCode,omitempty"`
}

// ReferenceLock records immutable or unresolved reference identity for a
// template field without proving mutable remote identity.
type ReferenceLock struct {
	Field      string                          `json:"field,omitempty"`
	Kind       sandboxtemplate.ReferenceKind   `json:"kind,omitempty"`
	Status     LockStatus                      `json:"status,omitempty"`
	Digest     *sandboxtemplate.DigestMetadata `json:"digest,omitempty"`
	ReasonCode LockReasonCode                  `json:"reasonCode,omitempty"`
}

// OCIArtifactResolver resolves OCI-like artifact metadata through injected,
// fake-safe implementations. Production acquisition code must not create live
// registry clients directly.
type OCIArtifactResolver interface {
	ResolveOCIArtifact(context.Context, OCIArtifactResolveRequest) (OCIArtifactResolveResult, error)
}

// OCIArtifactResolveRequest identifies the template artifact to load.
type OCIArtifactResolveRequest struct {
	Reference sandboxtemplate.ImmutableRef `json:"reference"`
}

// OCIArtifactResolveResult is fixture-provided artifact content and immutable
// identity proof returned by an injected resolver.
type OCIArtifactResolveResult struct {
	TemplateBytes          []byte                          `json:"templateBytes,omitempty"`
	ArtifactManifestBytes  []byte                          `json:"artifactManifestBytes,omitempty"`
	Format                 sandboxtemplate.Format          `json:"format,omitempty"`
	DocumentDigest         *sandboxtemplate.DigestMetadata `json:"documentDigest,omitempty"`
	TemplateArtifactDigest *sandboxtemplate.DigestMetadata `json:"templateArtifactDigest,omitempty"`
	ReferenceDigests       []ReferenceDigestProof          `json:"referenceDigests,omitempty"`
	SizeBytes              int64                           `json:"sizeBytes,omitempty"`
}

// ReferenceDigestProof records immutable identity for a reference discovered
// while resolving a template artifact.
type ReferenceDigestProof struct {
	Field         string                          `json:"field,omitempty"`
	Kind          sandboxtemplate.ReferenceKind   `json:"kind,omitempty"`
	Ref           string                          `json:"ref,omitempty"`
	Digest        *sandboxtemplate.DigestMetadata `json:"digest,omitempty"`
	VerifiedBytes []byte                          `json:"verifiedBytes,omitempty"`
}

// GitTemplateResolver resolves Git-hosted template metadata through injected,
// fake-safe implementations. Production acquisition code must not create live
// clients directly.
type GitTemplateResolver interface {
	ResolveGitTemplate(context.Context, GitTemplateResolveRequest) (GitTemplateResolveResult, error)
}

// GitTemplateResolveRequest identifies the template document to load.
type GitTemplateResolveRequest struct {
	Reference sandboxtemplate.ImmutableRef `json:"reference"`
}

// GitTemplateResolveResult is fixture-provided template content and optional
// immutable identity proof returned by an injected resolver.
type GitTemplateResolveResult struct {
	TemplateBytes    []byte                          `json:"templateBytes,omitempty"`
	Format           sandboxtemplate.Format          `json:"format,omitempty"`
	DocumentDigest   *sandboxtemplate.DigestMetadata `json:"documentDigest,omitempty"`
	SourceDigest     *sandboxtemplate.DigestMetadata `json:"sourceDigest,omitempty"`
	ReferenceDigests []ReferenceDigestProof          `json:"referenceDigests,omitempty"`
	SizeBytes        int64                           `json:"sizeBytes,omitempty"`
}

// LocalResolver resolves local YAML or JSON template documents.
type LocalResolver struct{}

func NewLocalResolver() LocalResolver {
	return LocalResolver{}
}

// OCIResolver resolves OCI-like template artifacts through an injected
// OCIArtifactResolver. Fake-safe resolution is implemented in a later story.
type OCIResolver struct {
	artifactResolver OCIArtifactResolver
}

func NewOCIResolver(resolver OCIArtifactResolver) OCIResolver {
	return OCIResolver{artifactResolver: resolver}
}

// GitResolver resolves Git-hosted template documents through an injected
// GitTemplateResolver. Default code paths stay deterministic and fake-safe.
type GitResolver struct {
	templateResolver GitTemplateResolver
}

func NewGitResolver(resolver GitTemplateResolver) GitResolver {
	return GitResolver{templateResolver: resolver}
}

// DispatchResolverOptions wires deterministic acquisition adapters by source
// kind. Local defaults to NewLocalResolver; remote sources require injected
// adapters.
type DispatchResolverOptions struct {
	Local Resolver
	Git   GitTemplateResolver
	OCI   OCIArtifactResolver
}

// DispatchResolver selects the deterministic resolver for a classified
// TemplateSource.
type DispatchResolver struct {
	local Resolver
	git   Resolver
	oci   Resolver
}

func NewDispatchResolver(options DispatchResolverOptions) DispatchResolver {
	local := options.Local
	if local == nil {
		local = NewLocalResolver()
	}
	var git Resolver
	if options.Git != nil {
		git = NewGitResolver(options.Git)
	}
	var oci Resolver
	if options.OCI != nil {
		oci = NewOCIResolver(options.OCI)
	}
	return DispatchResolver{
		local: local,
		git:   git,
		oci:   oci,
	}
}
