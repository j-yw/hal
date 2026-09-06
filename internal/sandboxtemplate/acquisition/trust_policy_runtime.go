package acquisition

import "github.com/jywlabs/hal/internal/sandboxruntime"

// ProjectRuntimeTemplateLockMetadata maps sanitized provenance and trust policy
// output into runtime-local template lock metadata for selection callers.
func ProjectRuntimeTemplateLockMetadata(projection *TemplateProvenanceProjection, result TrustPolicyResult) *sandboxruntime.RuntimeTemplateLockMetadata {
	projection = SanitizeTemplateProvenanceProjection(projection)
	metadata := &sandboxruntime.RuntimeTemplateLockMetadata{
		TrustPolicy: runtimeTemplateTrustPolicyMetadata(projection, result),
	}
	if projection != nil {
		metadata.Document = runtimeTemplateLockEntryMetadata(projection.Document)
		metadata.TemplateReference = runtimeTemplateLockEntryMetadata(projection.TemplateReference)
		metadata.RuntimeImage = runtimeTemplateLockEntryMetadata(projection.RuntimeImage)
		metadata.SourceArtifact = runtimeTemplateLockEntryMetadata(projection.SourceArtifact)
	}
	return sandboxruntime.SanitizeRuntimeTemplateLockMetadata(metadata)
}

func runtimeTemplateLockEntryMetadata(entry *TemplateProvenanceEntry) *sandboxruntime.RuntimeTemplateLockEntryMetadata {
	if entry == nil {
		return nil
	}
	return &sandboxruntime.RuntimeTemplateLockEntryMetadata{
		SourceKind:      entry.SourceKind,
		ReferenceKind:   entry.ReferenceKind,
		Status:          entry.Status,
		DigestAlgorithm: entry.DigestAlgorithm,
		DigestValue:     entry.DigestValue,
		SizeBytes:       entry.SizeBytes,
		LockedAt:        entry.LockedAt,
		WarningCodes:    append([]string(nil), entry.WarningCodes...),
		ReasonCode:      entry.ReasonCode,
	}
}

func runtimeTemplateTrustPolicyMetadata(projection *TemplateProvenanceProjection, result TrustPolicyResult) *sandboxruntime.RuntimeTemplateTrustPolicyMetadata {
	if result.Mode == "" && result.Decision == "" && len(result.Errors) == 0 && len(result.Warnings) == 0 {
		return nil
	}
	identity := runtimeTemplateTrustPolicyIdentity(projection)
	policy := &sandboxruntime.RuntimeTemplateTrustPolicyMetadata{
		Mode:         string(result.Mode),
		Decision:     string(result.Decision),
		WarningCodes: runtimeTemplateTrustPolicyWarningCodes(result.Warnings),
		ErrorCodes:   runtimeTemplateTrustPolicyErrorCodes(result.Errors),
		ReasonCodes:  runtimeTemplateTrustPolicyReasonCodes(result.Errors, result.Warnings),
	}
	if identity != nil {
		policy.SourceKind = identity.SourceKind
		policy.ReferenceKind = identity.ReferenceKind
		policy.Status = identity.Status
		policy.DigestAlgorithm = identity.DigestAlgorithm
		policy.DigestValue = identity.DigestValue
	}
	return policy
}

func runtimeTemplateTrustPolicyIdentity(projection *TemplateProvenanceProjection) *TemplateProvenanceEntry {
	if projection == nil {
		return nil
	}
	if projection.Document != nil {
		return projection.Document
	}
	if projection.TemplateReference != nil {
		return projection.TemplateReference
	}
	if projection.RuntimeImage != nil {
		return projection.RuntimeImage
	}
	return projection.SourceArtifact
}

func runtimeTemplateTrustPolicyWarningCodes(warnings []TrustPolicyWarning) []string {
	if len(warnings) == 0 {
		return nil
	}
	codes := make([]string, 0, len(warnings))
	for _, warning := range warnings {
		codes = append(codes, string(warning.Code))
	}
	return codes
}

func runtimeTemplateTrustPolicyErrorCodes(errors []TrustPolicyError) []string {
	if len(errors) == 0 {
		return nil
	}
	codes := make([]string, 0, len(errors))
	for _, err := range errors {
		codes = append(codes, string(err.Code))
	}
	return codes
}

func runtimeTemplateTrustPolicyReasonCodes(errors []TrustPolicyError, warnings []TrustPolicyWarning) []string {
	codes := make([]string, 0, len(errors)+len(warnings))
	for _, err := range errors {
		codes = append(codes, string(err.ReasonCode))
	}
	for _, warning := range warnings {
		codes = append(codes, string(warning.ReasonCode))
	}
	return codes
}
