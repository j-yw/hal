// Package selection owns the transport-independent L9 template-selection
// workflow. It acquires, digest-canonicalizes, evaluates, and binds one
// immutable template before command code constructs a target or runtime.
package selection

import (
	"context"
	"errors"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxtemplate"
	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition"
)

type ErrorCode string

const ErrorCodeSelectionRejected ErrorCode = "selection_rejected"

var ErrSelectionRejected = errors.New("sandbox template selection rejected")

type Error struct {
	Code ErrorCode
	Err  error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return string(e.Code)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

type Workflow struct {
	resolver acquisition.Resolver
}

func NewWorkflow(resolver acquisition.Resolver) Workflow {
	return Workflow{resolver: resolver}
}

type Request struct {
	Source             acquisition.TemplateSource
	TrustMode          acquisition.TrustPolicyMode
	LockedAtUnixMillis int64
}

type Result struct {
	Template        sandboxtemplate.Template
	Lock            acquisition.TemplateLock
	Provenance      *acquisition.TemplateProvenanceProjection
	Trust           acquisition.TrustPolicyResult
	RuntimeMetadata *sandboxruntime.RuntimeTemplateLockMetadata
	RuntimeDriver   string
	IsolationLevel  string
	ManifestDigest  *sandboxtemplate.DigestMetadata
}

func (w Workflow) Select(ctx context.Context, request Request) (Result, error) {
	if w.resolver == nil {
		return Result{}, rejected(acquisition.ErrResolverUnavailable)
	}
	resolved, err := w.resolver.Resolve(ctx, acquisition.ResolveRequest{
		Source:             request.Source,
		LockedAtUnixMillis: request.LockedAtUnixMillis,
	})
	if err != nil {
		return Result{}, err
	}
	manifestDigest := selectedManifestDigest(resolved.Lock)
	if manifestDigest == nil {
		return Result{}, rejected(ErrSelectionRejected)
	}

	template := resolved.Template
	template.Metadata.Reference = &sandboxtemplate.ImmutableRef{
		Kind:   sandboxtemplate.ReferenceKindOCIArtifact,
		Digest: cloneDigest(manifestDigest),
	}
	provenance := acquisition.ProjectTemplateProvenance(resolved.Lock)
	trust := acquisition.EvaluateTrustPolicy(template, acquisition.TrustPolicyRequest{
		Mode: request.TrustMode,
		Source: &acquisition.TrustPolicySource{
			Kind:          acquisition.SourceKindOCIArtifact,
			ReferenceKind: sandboxtemplate.ReferenceKindOCIArtifact,
			Digest:        cloneDigest(manifestDigest),
		},
		Lock:       &resolved.Lock,
		Provenance: &resolved.Lock,
	})
	if request.TrustMode != acquisition.TrustPolicyModeAdvisory &&
		trust.Decision != acquisition.TrustPolicyDecisionTrusted {
		return Result{}, rejected(ErrSelectionRejected)
	}

	result := Result{
		Template:        template,
		Lock:            resolved.Lock,
		Provenance:      provenance,
		Trust:           trust,
		RuntimeMetadata: acquisition.ProjectRuntimeTemplateLockMetadata(provenance, trust),
		ManifestDigest:  cloneDigest(manifestDigest),
	}
	if template.Runtime != nil {
		result.RuntimeDriver = string(template.Runtime.Driver)
		result.IsolationLevel = string(template.Runtime.IsolationLevel)
	}
	return result, nil
}

type BindingRequest struct {
	ExecutionID    string
	SandboxID      string
	RuntimeID      string
	RuntimeDriver  string
	ManifestDigest *sandboxtemplate.DigestMetadata
}

type Binding struct {
	ExecutionID     string
	SandboxID       string
	RuntimeID       string
	RuntimeDriver   string
	ManifestDigest  *sandboxtemplate.DigestMetadata
	RuntimeMetadata *sandboxruntime.RuntimeTemplateLockMetadata
}

func Bind(result Result, request BindingRequest) (Binding, error) {
	if strings.TrimSpace(request.ExecutionID) == "" ||
		strings.TrimSpace(request.SandboxID) == "" ||
		strings.TrimSpace(request.RuntimeID) == "" ||
		strings.TrimSpace(request.RuntimeDriver) == "" ||
		result.ManifestDigest == nil ||
		request.ManifestDigest == nil ||
		!digestEqual(result.ManifestDigest, request.ManifestDigest) ||
		strings.TrimSpace(result.RuntimeDriver) != strings.TrimSpace(request.RuntimeDriver) {
		return Binding{}, rejected(ErrSelectionRejected)
	}
	return Binding{
		ExecutionID:     strings.TrimSpace(request.ExecutionID),
		SandboxID:       strings.TrimSpace(request.SandboxID),
		RuntimeID:       strings.TrimSpace(request.RuntimeID),
		RuntimeDriver:   strings.TrimSpace(request.RuntimeDriver),
		ManifestDigest:  cloneDigest(result.ManifestDigest),
		RuntimeMetadata: sandboxruntime.SanitizeRuntimeTemplateLockMetadata(result.RuntimeMetadata),
	}, nil
}

func selectedManifestDigest(lock acquisition.TemplateLock) *sandboxtemplate.DigestMetadata {
	for _, reference := range lock.References {
		if reference.Field == "metadata.reference" &&
			reference.Status == acquisition.LockStatusLocked &&
			reference.Digest != nil {
			return cloneDigest(reference.Digest)
		}
	}
	return nil
}

func cloneDigest(digest *sandboxtemplate.DigestMetadata) *sandboxtemplate.DigestMetadata {
	if digest == nil {
		return nil
	}
	return &sandboxtemplate.DigestMetadata{Algorithm: digest.Algorithm, Value: digest.Value}
}

func digestEqual(left, right *sandboxtemplate.DigestMetadata) bool {
	return left != nil && right != nil && left.Algorithm == right.Algorithm && left.Value == right.Value
}

func rejected(err error) *Error {
	return &Error{Code: ErrorCodeSelectionRejected, Err: err}
}
