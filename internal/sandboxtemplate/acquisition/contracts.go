// Package acquisition defines sandbox template acquisition contracts.
//
// This package intentionally contains contract shape only in US-001. Local
// file resolution behavior is introduced by the later implementation story.
package acquisition

import (
	"context"
	"errors"

	"github.com/jywlabs/hal/internal/sandboxtemplate"
)

const (
	SourceKindLocalFile SourceKind = "local_file"
)

const (
	LockStatusLocked     LockStatus = "locked"
	LockStatusUnresolved LockStatus = "unresolved"
)

const (
	LockReasonMutableReference    LockReasonCode = "mutable_reference"
	LockReasonImmutableDigest     LockReasonCode = "immutable_digest"
	LockReasonDocumentDigest      LockReasonCode = "document_digest"
	LockReasonResolverUnavailable LockReasonCode = "resolver_unavailable"
)

var ErrResolverUnavailable = errors.New("local template acquisition resolver is unavailable")

type SourceKind string
type LockStatus string
type LockReasonCode string

// ResolveRequest describes one sandbox template acquisition request.
type ResolveRequest struct {
	Source             TemplateSource `json:"source"`
	LockedAtUnixMillis int64          `json:"lockedAtUnixMillis,omitempty"`
}

// TemplateSource describes the requested template source without durable
// persistence requirements. LocalPath is caller input and must not be copied
// into persisted lock metadata.
type TemplateSource struct {
	Kind      SourceKind             `json:"kind"`
	LocalPath string                 `json:"localPath,omitempty"`
	Format    sandboxtemplate.Format `json:"format,omitempty"`
}

// ResolveResult is the resolved template plus redaction-safe acquisition lock
// metadata.
type ResolveResult struct {
	Template sandboxtemplate.Template `json:"template"`
	Lock     TemplateLock             `json:"lock"`
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

// LocalResolver resolves local YAML or JSON template documents.
type LocalResolver struct{}

func NewLocalResolver() LocalResolver {
	return LocalResolver{}
}

func (LocalResolver) Resolve(context.Context, ResolveRequest) (ResolveResult, error) {
	return ResolveResult{}, ErrResolverUnavailable
}
