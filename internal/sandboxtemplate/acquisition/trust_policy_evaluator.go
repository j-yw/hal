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
	if trustPolicyDocumentLocked(lock) || trustPolicyDocumentLocked(provenance) {
		return
	}
	if trustPolicyDocumentUnresolved(lock) || trustPolicyDocumentUnresolved(provenance) {
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

	if trustPolicyReferenceLocked(lock, field, requirement.Kind) || trustPolicyReferenceLocked(provenance, field, requirement.Kind) {
		return
	}
	if trustPolicyReferenceUnresolved(lock, field, requirement.Kind) || trustPolicyReferenceUnresolved(provenance, field, requirement.Kind) {
		e.addFinding(
			TrustPolicyErrorUnresolvedLockEntry,
			TrustPolicyWarningUnresolvedLockEntry,
			trustPolicyFieldRequiredReferences,
			field,
			&referenceIndex,
			LockReasonMutableReference,
			trustPolicyUnresolvedLockMessage,
		)
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

func trustPolicyReferenceLocked(lock *TemplateLock, field string, kind sandboxtemplate.ReferenceKind) bool {
	if lock == nil {
		return false
	}
	for _, reference := range lock.References {
		if !trustPolicyReferenceLockMatches(reference, field, kind) {
			continue
		}
		if reference.Status == LockStatusLocked && trustPolicyDigestPinned(reference.Digest) {
			return true
		}
	}
	return false
}

func trustPolicyReferenceUnresolved(lock *TemplateLock, field string, kind sandboxtemplate.ReferenceKind) bool {
	if lock == nil {
		return false
	}
	for _, reference := range lock.References {
		if !trustPolicyReferenceLockMatches(reference, field, kind) {
			continue
		}
		if reference.Status == LockStatusUnresolved {
			return true
		}
	}
	return false
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
	case len(e.result.Errors) > 0:
		e.result.Decision = TrustPolicyDecisionRejected
	case len(e.result.Warnings) > 0:
		e.result.Decision = TrustPolicyDecisionAdvisory
	default:
		e.result.Decision = TrustPolicyDecisionTrusted
	}
}
