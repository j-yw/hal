package acquisition

import "github.com/jywlabs/hal/internal/sandboxtemplate"

const (
	TrustPolicyModeStrict   TrustPolicyMode = "strict"
	TrustPolicyModeAdvisory TrustPolicyMode = "advisory"
)

const (
	TrustPolicyDecisionTrusted     TrustPolicyDecision = "trusted"
	TrustPolicyDecisionRejected    TrustPolicyDecision = "rejected"
	TrustPolicyDecisionAdvisory    TrustPolicyDecision = "advisory"
	TrustPolicyDecisionUnavailable TrustPolicyDecision = "unavailable"
)

const (
	TrustPolicyErrorMutableReference       TrustPolicyErrorCode = "mutable_reference"
	TrustPolicyErrorMissingDigestPin       TrustPolicyErrorCode = "missing_digest_pin"
	TrustPolicyErrorUnresolvedLockEntry    TrustPolicyErrorCode = "unresolved_lock_entry"
	TrustPolicyErrorLockProvenanceMismatch TrustPolicyErrorCode = "lock_provenance_mismatch"
	TrustPolicyErrorUnsupportedSource      TrustPolicyErrorCode = "unsupported_source"
	TrustPolicyErrorResolverUnavailable    TrustPolicyErrorCode = "resolver_unavailable"
)

const (
	TrustPolicyWarningMutableReference       TrustPolicyWarningCode = "mutable_reference"
	TrustPolicyWarningMissingDigestPin       TrustPolicyWarningCode = "missing_digest_pin"
	TrustPolicyWarningUnresolvedLockEntry    TrustPolicyWarningCode = "unresolved_lock_entry"
	TrustPolicyWarningLockProvenanceMismatch TrustPolicyWarningCode = "lock_provenance_mismatch"
	TrustPolicyWarningUnsupportedSource      TrustPolicyWarningCode = "unsupported_source"
	TrustPolicyWarningResolverUnavailable    TrustPolicyWarningCode = "resolver_unavailable"
)

type TrustPolicyMode string
type TrustPolicyDecision string
type TrustPolicyErrorCode string
type TrustPolicyWarningCode string

// TrustPolicyRequest carries redaction-safe template acquisition metadata for
// policy evaluation. It intentionally omits caller-local source paths, raw
// registry references, auth material, command metadata, and runtime startup
// metadata.
type TrustPolicyRequest struct {
	Mode               TrustPolicyMode                   `json:"mode,omitempty"`
	Source             *TrustPolicySource                `json:"source,omitempty"`
	RequiredReferences []TrustPolicyReferenceRequirement `json:"requiredReferences,omitempty"`
	Lock               *TemplateLock                     `json:"lock,omitempty"`
	Provenance         *TemplateLock                     `json:"provenance,omitempty"`
}

// TrustPolicySource identifies the acquired source using only safe categories
// and digest identity.
type TrustPolicySource struct {
	Kind          SourceKind                      `json:"kind,omitempty"`
	ReferenceKind sandboxtemplate.ReferenceKind   `json:"referenceKind,omitempty"`
	Digest        *sandboxtemplate.DigestMetadata `json:"digest,omitempty"`
}

// TrustPolicyReferenceRequirement names a template reference role that a later
// evaluator may require to be digest-pinned or proven by acquisition metadata.
type TrustPolicyReferenceRequirement struct {
	Field string                        `json:"field"`
	Kind  sandboxtemplate.ReferenceKind `json:"kind,omitempty"`
}

// TrustPolicyResult is the redaction-safe output shape for template trust
// policy evaluation.
type TrustPolicyResult struct {
	Mode        TrustPolicyMode                 `json:"mode,omitempty"`
	Decision    TrustPolicyDecision             `json:"decision"`
	Enforcement *TrustPolicyEnforcementMetadata `json:"enforcement,omitempty"`
	Errors      []TrustPolicyError              `json:"errors,omitempty"`
	Warnings    []TrustPolicyWarning            `json:"warnings,omitempty"`
}

// TrustPolicyEnforcementMetadata makes advisory evaluation explicit in durable
// policy output without implying that mutable references were trusted.
type TrustPolicyEnforcementMetadata struct {
	StrictlyEnforced bool `json:"strictlyEnforced"`
}

// TrustPolicyError identifies a policy rejection without echoing rejected
// source values or resolver inputs.
type TrustPolicyError struct {
	Code           TrustPolicyErrorCode `json:"code"`
	Field          string               `json:"field,omitempty"`
	ReferenceField string               `json:"referenceField,omitempty"`
	ReferenceIndex *int                 `json:"referenceIndex,omitempty"`
	SourceKind     SourceKind           `json:"sourceKind,omitempty"`
	ReasonCode     LockReasonCode       `json:"reasonCode,omitempty"`
	Message        string               `json:"message,omitempty"`
}

// TrustPolicyWarning identifies an advisory policy finding without echoing
// rejected source values or resolver inputs.
type TrustPolicyWarning struct {
	Code           TrustPolicyWarningCode `json:"code"`
	Field          string                 `json:"field,omitempty"`
	ReferenceField string                 `json:"referenceField,omitempty"`
	ReferenceIndex *int                   `json:"referenceIndex,omitempty"`
	SourceKind     SourceKind             `json:"sourceKind,omitempty"`
	ReasonCode     LockReasonCode         `json:"reasonCode,omitempty"`
	Message        string                 `json:"message,omitempty"`
}
