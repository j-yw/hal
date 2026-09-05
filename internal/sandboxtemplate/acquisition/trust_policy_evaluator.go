package acquisition

import (
	"strings"

	"github.com/jywlabs/hal/internal/sandboxtemplate"
)

const (
	trustPolicyFieldMetadataReference       = "metadata.reference"
	trustPolicyFieldRuntimeImage            = "runtime.image"
	trustPolicyFieldRuntimeDescriptorRef    = "runtime.launch.descriptorRef"
	trustPolicyFieldWorkspaceRef            = "workspace.ref"
	trustPolicyFieldNetworkPolicySnapshot   = "network.policySnapshotReference"
	trustPolicyFieldRequiredReferences      = "requiredReferences"
	trustPolicyFieldTemplateDocumentLock    = "lock.document"
	trustPolicyMissingDigestMessage         = "required reference is not digest pinned"
	trustPolicyUnresolvedLockMessage        = "required reference lock is unresolved"
	trustPolicyMissingDocumentDigestMessage = "template document digest is not locked"
	trustPolicyProvenanceMismatchMessage    = "required reference provenance does not match locked digest"
	trustPolicyDocumentMismatchMessage      = "template document provenance does not match locked digest"
	trustPolicyResolverUnavailableMessage   = "resolver is unavailable"
	trustPolicyUnsupportedSourceMessage     = "template source is unsupported"
)

// EvaluateTrustPolicy evaluates sanitized template metadata against strict or
// advisory acquisition trust policy without resolving references or touching
// runtime/provider surfaces.
func EvaluateTrustPolicy(template sandboxtemplate.Template, request TrustPolicyRequest) TrustPolicyResult {
	mode := normalizeTrustPolicyMode(request.Mode)
	evaluation := trustPolicyEvaluation{
		mode: mode,
		result: TrustPolicyResult{
			Mode: mode,
			Enforcement: &TrustPolicyEnforcementMetadata{
				StrictlyEnforced: mode == TrustPolicyModeStrict,
			},
		},
	}

	safeTemplate := sandboxtemplate.SanitizeTemplate(template)
	evaluation.requireTemplateDocumentIdentity(request.Lock, request.Provenance)

	requirements := request.RequiredReferences
	if len(requirements) == 0 {
		requirements = trustPolicyPresentReferenceRequirements(safeTemplate)
	}
	for i, requirement := range requirements {
		evaluation.requireReferenceDigestPin(safeTemplate, request.Lock, request.Provenance, i, requirement)
	}

	evaluation.requireStrictTrustedEvidence(request.Lock, request.Provenance)
	evaluation.finalize()
	return evaluation.result
}

type trustPolicyEvaluation struct {
	mode   TrustPolicyMode
	result TrustPolicyResult
}

func normalizeTrustPolicyMode(mode TrustPolicyMode) TrustPolicyMode {
	switch mode {
	case TrustPolicyModeAdvisory:
		return TrustPolicyModeAdvisory
	default:
		return TrustPolicyModeStrict
	}
}

func (e *trustPolicyEvaluation) requireTemplateDocumentIdentity(lock *TemplateLock, provenance *TemplateLock) {
	if reason := trustPolicyTemplateLockBlockingReason(lock); reason != "" {
		e.addUnavailableFinding(trustPolicyFieldTemplateDocumentLock, "", nil, reason)
		return
	}
	if reason := trustPolicyTemplateLockBlockingReason(provenance); reason != "" {
		e.addUnavailableFinding(trustPolicyFieldTemplateDocumentLock, "", nil, reason)
		return
	}
	if trustPolicyDocumentLocked(lock) {
		if provenance != nil && !trustPolicyDocumentMatches(lock.Document, provenance.Document) {
			e.addFinding(
				TrustPolicyErrorLockProvenanceMismatch,
				TrustPolicyWarningLockProvenanceMismatch,
				trustPolicyFieldTemplateDocumentLock,
				"",
				nil,
				LockReasonDocumentDigest,
				trustPolicyDocumentMismatchMessage,
			)
		}
		return
	}
	if trustPolicyDocumentUnresolved(lock) {
		e.addFinding(
			TrustPolicyErrorUnresolvedLockEntry,
			TrustPolicyWarningUnresolvedLockEntry,
			trustPolicyFieldTemplateDocumentLock,
			"",
			nil,
			LockReasonDocumentDigest,
			trustPolicyMissingDocumentDigestMessage,
		)
		return
	}
	if lock != nil {
		e.addFinding(
			TrustPolicyErrorMissingDigestPin,
			TrustPolicyWarningMissingDigestPin,
			trustPolicyFieldTemplateDocumentLock,
			"",
			nil,
			LockReasonDocumentDigest,
			trustPolicyMissingDocumentDigestMessage,
		)
		return
	}
	if trustPolicyDocumentLocked(provenance) {
		return
	}
	if trustPolicyDocumentUnresolved(provenance) {
		e.addFinding(
			TrustPolicyErrorUnresolvedLockEntry,
			TrustPolicyWarningUnresolvedLockEntry,
			trustPolicyFieldTemplateDocumentLock,
			"",
			nil,
			LockReasonDocumentDigest,
			trustPolicyMissingDocumentDigestMessage,
		)
		return
	}
	e.addFinding(
		TrustPolicyErrorMissingDigestPin,
		TrustPolicyWarningMissingDigestPin,
		trustPolicyFieldTemplateDocumentLock,
		"",
		nil,
		LockReasonDocumentDigest,
		trustPolicyMissingDocumentDigestMessage,
	)
}

func trustPolicyDocumentLocked(lock *TemplateLock) bool {
	return lock != nil &&
		lock.Document.Status == LockStatusLocked &&
		trustPolicyDigestPinned(lock.Document.Digest)
}

func trustPolicyDocumentUnresolved(lock *TemplateLock) bool {
	return lock != nil && lock.Document.Status == LockStatusUnresolved
}

func trustPolicyDocumentMatches(lock DigestLock, provenance DigestLock) bool {
	return trustPolicyDocumentLockDigestPinned(lock) &&
		trustPolicyDocumentLockDigestPinned(provenance) &&
		trustPolicyDigestEqual(lock.Digest, provenance.Digest)
}

func trustPolicyDocumentLockDigestPinned(lock DigestLock) bool {
	return lock.Status == LockStatusLocked && trustPolicyDigestPinned(lock.Digest)
}

func (e *trustPolicyEvaluation) requireReferenceDigestPin(template sandboxtemplate.Template, lock *TemplateLock, provenance *TemplateLock, index int, requirement TrustPolicyReferenceRequirement) {
	field := trustPolicyKnownReferenceField(requirement.Field)
	referenceIndex := index
	if field == "" {
		e.addFinding(
			TrustPolicyErrorMissingDigestPin,
			TrustPolicyWarningMissingDigestPin,
			trustPolicyFieldRequiredReferences,
			"",
			&referenceIndex,
			LockReasonMutableReference,
			trustPolicyMissingDigestMessage,
		)
		return
	}

	ref := trustPolicyTemplateReference(template, field)
	if ref == nil || (requirement.Kind != "" && ref.Kind != "" && requirement.Kind != ref.Kind) {
		e.addFinding(
			TrustPolicyErrorMissingDigestPin,
			TrustPolicyWarningMissingDigestPin,
			trustPolicyFieldRequiredReferences,
			field,
			&referenceIndex,
			LockReasonMutableReference,
			trustPolicyMissingDigestMessage,
		)
		return
	}

	lockReference, hasLockReference := trustPolicyReferenceLockEntry(lock, field, requirement.Kind)
	provenanceReference, hasProvenanceReference := trustPolicyReferenceLockEntry(provenance, field, requirement.Kind)
	if hasLockReference {
		if lockReference.Status == LockStatusUnresolved {
			if reason := trustPolicyBlockingReason(lockReference.ReasonCode); reason != "" {
				e.addUnavailableFinding(
					trustPolicyFieldRequiredReferences,
					field,
					&referenceIndex,
					reason,
				)
				return
			}
			e.addFinding(
				TrustPolicyErrorUnresolvedLockEntry,
				TrustPolicyWarningUnresolvedLockEntry,
				trustPolicyFieldRequiredReferences,
				field,
				&referenceIndex,
				trustPolicyReferenceReason(lockReference, LockReasonMutableReference),
				trustPolicyUnresolvedLockMessage,
			)
			return
		}
		if !sandboxtemplate.ReferenceDigestPinned(ref) {
			e.addFinding(
				TrustPolicyErrorMutableReference,
				TrustPolicyWarningMutableReference,
				trustPolicyFieldRequiredReferences,
				field,
				&referenceIndex,
				LockReasonMutableReference,
				trustPolicyMissingDigestMessage,
			)
			return
		}
		if trustPolicyReferenceLockDigestPinned(lockReference) {
			if provenance != nil && (!hasProvenanceReference || !trustPolicyReferenceLockDigestPinned(provenanceReference) || !trustPolicyDigestEqual(lockReference.Digest, provenanceReference.Digest)) {
				e.addFinding(
					TrustPolicyErrorLockProvenanceMismatch,
					TrustPolicyWarningLockProvenanceMismatch,
					trustPolicyFieldRequiredReferences,
					field,
					&referenceIndex,
					LockReasonImmutableDigest,
					trustPolicyProvenanceMismatchMessage,
				)
			}
			return
		}
		e.addFinding(
			TrustPolicyErrorMissingDigestPin,
			TrustPolicyWarningMissingDigestPin,
			trustPolicyFieldRequiredReferences,
			field,
			&referenceIndex,
			trustPolicyReferenceReason(lockReference, LockReasonImmutableDigest),
			trustPolicyMissingDigestMessage,
		)
		return
	}
	if hasProvenanceReference && provenanceReference.Status == LockStatusUnresolved {
		if reason := trustPolicyBlockingReason(provenanceReference.ReasonCode); reason != "" {
			e.addUnavailableFinding(
				trustPolicyFieldRequiredReferences,
				field,
				&referenceIndex,
				reason,
			)
			return
		}
		e.addFinding(
			TrustPolicyErrorUnresolvedLockEntry,
			TrustPolicyWarningUnresolvedLockEntry,
			trustPolicyFieldRequiredReferences,
			field,
			&referenceIndex,
			trustPolicyReferenceReason(provenanceReference, LockReasonMutableReference),
			trustPolicyUnresolvedLockMessage,
		)
		return
	}
	if !sandboxtemplate.ReferenceDigestPinned(ref) {
		e.addFinding(
			TrustPolicyErrorMutableReference,
			TrustPolicyWarningMutableReference,
			trustPolicyFieldRequiredReferences,
			field,
			&referenceIndex,
			LockReasonMutableReference,
			trustPolicyMissingDigestMessage,
		)
		return
	}
	if lock != nil {
		e.addFinding(
			TrustPolicyErrorMissingDigestPin,
			TrustPolicyWarningMissingDigestPin,
			trustPolicyFieldRequiredReferences,
			field,
			&referenceIndex,
			LockReasonMutableReference,
			trustPolicyMissingDigestMessage,
		)
		return
	}
	if hasProvenanceReference && trustPolicyReferenceLockDigestPinned(provenanceReference) {
		return
	}
	if sandboxtemplate.ReferenceDigestPinned(ref) {
		return
	}

	e.addFinding(
		TrustPolicyErrorMissingDigestPin,
		TrustPolicyWarningMutableReference,
		trustPolicyFieldRequiredReferences,
		field,
		&referenceIndex,
		LockReasonMutableReference,
		trustPolicyMissingDigestMessage,
	)
}

func (e *trustPolicyEvaluation) requireStrictTrustedEvidence(lock *TemplateLock, provenance *TemplateLock) {
	if e.mode != TrustPolicyModeStrict || len(e.result.Errors) > 0 || len(e.result.Warnings) > 0 {
		return
	}
	if lock == nil || provenance == nil || !trustPolicyDocumentMatches(lock.Document, provenance.Document) {
		e.addFinding(
			TrustPolicyErrorLockProvenanceMismatch,
			TrustPolicyWarningLockProvenanceMismatch,
			trustPolicyFieldTemplateDocumentLock,
			"",
			nil,
			LockReasonDocumentDigest,
			trustPolicyDocumentMismatchMessage,
		)
	}
}

func trustPolicyKnownReferenceField(field string) string {
	switch strings.TrimSpace(field) {
	case trustPolicyFieldMetadataReference:
		return trustPolicyFieldMetadataReference
	case trustPolicyFieldRuntimeImage:
		return trustPolicyFieldRuntimeImage
	case trustPolicyFieldRuntimeDescriptorRef:
		return trustPolicyFieldRuntimeDescriptorRef
	case trustPolicyFieldWorkspaceRef:
		return trustPolicyFieldWorkspaceRef
	case trustPolicyFieldNetworkPolicySnapshot:
		return trustPolicyFieldNetworkPolicySnapshot
	default:
		return ""
	}
}

func trustPolicyTemplateReference(template sandboxtemplate.Template, field string) *sandboxtemplate.ImmutableRef {
	switch field {
	case trustPolicyFieldMetadataReference:
		return template.Metadata.Reference
	case trustPolicyFieldRuntimeImage:
		if template.Runtime == nil {
			return nil
		}
		return template.Runtime.Image
	case trustPolicyFieldRuntimeDescriptorRef:
		if template.Runtime == nil || template.Runtime.Launch == nil {
			return nil
		}
		return template.Runtime.Launch.DescriptorRef
	case trustPolicyFieldWorkspaceRef:
		if template.Workspace == nil {
			return nil
		}
		return template.Workspace.Ref
	case trustPolicyFieldNetworkPolicySnapshot:
		if template.Network == nil {
			return nil
		}
		return template.Network.PolicySnapshotReference
	default:
		return nil
	}
}

func trustPolicyPresentReferenceRequirements(template sandboxtemplate.Template) []TrustPolicyReferenceRequirement {
	fields := []string{
		trustPolicyFieldMetadataReference,
		trustPolicyFieldRuntimeImage,
		trustPolicyFieldRuntimeDescriptorRef,
		trustPolicyFieldWorkspaceRef,
		trustPolicyFieldNetworkPolicySnapshot,
	}
	requirements := make([]TrustPolicyReferenceRequirement, 0, len(fields))
	for _, field := range fields {
		ref := trustPolicyTemplateReference(template, field)
		if ref == nil {
			continue
		}
		requirements = append(requirements, TrustPolicyReferenceRequirement{
			Field: field,
			Kind:  ref.Kind,
		})
	}
	if len(requirements) == 0 {
		return nil
	}
	return requirements
}

func trustPolicyReferenceLockEntry(lock *TemplateLock, field string, kind sandboxtemplate.ReferenceKind) (ReferenceLock, bool) {
	if lock == nil {
		return ReferenceLock{}, false
	}
	var fallback ReferenceLock
	hasFallback := false
	for _, reference := range lock.References {
		if !trustPolicyReferenceLockMatches(reference, field, kind) {
			continue
		}
		if kind != "" && reference.Kind == kind {
			return reference, true
		}
		if !hasFallback {
			fallback = reference
			hasFallback = true
		}
	}
	if hasFallback {
		return fallback, true
	}
	return ReferenceLock{}, false
}

func trustPolicyReferenceLockDigestPinned(reference ReferenceLock) bool {
	return reference.Status == LockStatusLocked && trustPolicyDigestPinned(reference.Digest)
}

func trustPolicyReferenceLockMatches(reference ReferenceLock, field string, kind sandboxtemplate.ReferenceKind) bool {
	if reference.Field != field {
		return false
	}
	return kind == "" || reference.Kind == "" || reference.Kind == kind
}

func trustPolicyDigestPinned(digest *sandboxtemplate.DigestMetadata) bool {
	return sandboxtemplate.ReferenceDigestPinned(&sandboxtemplate.ImmutableRef{Digest: digest})
}

func trustPolicyDigestEqual(left *sandboxtemplate.DigestMetadata, right *sandboxtemplate.DigestMetadata) bool {
	return trustPolicyDigestPinned(left) &&
		trustPolicyDigestPinned(right) &&
		left.Algorithm == right.Algorithm &&
		left.Value == right.Value
}

func trustPolicyTemplateLockBlockingReason(lock *TemplateLock) LockReasonCode {
	if lock == nil {
		return ""
	}
	if lock.SourceKind == SourceKindUnsupported {
		return LockReasonUnsupportedSource
	}
	for _, warning := range lock.Warnings {
		if reason := trustPolicyBlockingReason(warning); reason != "" {
			return reason
		}
	}
	return trustPolicyBlockingReason(lock.Document.ReasonCode)
}

func trustPolicyBlockingReason(reason LockReasonCode) LockReasonCode {
	switch reason {
	case LockReasonResolverUnavailable, LockReasonUnsupportedSource:
		return reason
	default:
		return ""
	}
}

func trustPolicyReferenceReason(reference ReferenceLock, fallback LockReasonCode) LockReasonCode {
	if templateProvenanceAllowedReasonCode(string(reference.ReasonCode)) {
		return reference.ReasonCode
	}
	return fallback
}

func (e *trustPolicyEvaluation) addUnavailableFinding(field string, referenceField string, referenceIndex *int, reason LockReasonCode) {
	errorCode, warningCode, message, ok := trustPolicyUnavailableFinding(reason)
	if !ok {
		return
	}
	e.addFinding(errorCode, warningCode, field, referenceField, referenceIndex, reason, message)
}

func trustPolicyUnavailableFinding(reason LockReasonCode) (TrustPolicyErrorCode, TrustPolicyWarningCode, string, bool) {
	switch reason {
	case LockReasonResolverUnavailable:
		return TrustPolicyErrorResolverUnavailable, TrustPolicyWarningResolverUnavailable, trustPolicyResolverUnavailableMessage, true
	case LockReasonUnsupportedSource:
		return TrustPolicyErrorUnsupportedSource, TrustPolicyWarningUnsupportedSource, trustPolicyUnsupportedSourceMessage, true
	default:
		return "", "", "", false
	}
}

func (e *trustPolicyEvaluation) addFinding(errorCode TrustPolicyErrorCode, warningCode TrustPolicyWarningCode, field string, referenceField string, referenceIndex *int, reason LockReasonCode, message string) {
	if e.mode == TrustPolicyModeAdvisory {
		warning := TrustPolicyWarning{
			Code:           warningCode,
			Field:          field,
			ReferenceField: referenceField,
			ReasonCode:     reason,
			Message:        message,
		}
		if referenceIndex != nil {
			value := *referenceIndex
			warning.ReferenceIndex = &value
		}
		e.result.Warnings = append(e.result.Warnings, warning)
		return
	}

	err := TrustPolicyError{
		Code:           errorCode,
		Field:          field,
		ReferenceField: referenceField,
		ReasonCode:     reason,
		Message:        message,
	}
	if referenceIndex != nil {
		value := *referenceIndex
		err.ReferenceIndex = &value
	}
	e.result.Errors = append(e.result.Errors, err)
}

func (e *trustPolicyEvaluation) finalize() {
	switch {
	case e.mode == TrustPolicyModeAdvisory:
		e.result.Decision = TrustPolicyDecisionAdvisory
	case len(e.result.Errors) > 0:
		e.result.Decision = TrustPolicyDecisionRejected
	case len(e.result.Warnings) > 0:
		e.result.Decision = TrustPolicyDecisionAdvisory
	default:
		e.result.Decision = TrustPolicyDecisionTrusted
	}
}
