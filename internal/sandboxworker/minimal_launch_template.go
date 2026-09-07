package sandboxworker

import "github.com/jywlabs/hal/internal/sandboxruntime"

// Copy only the typed ingress identity. No trust label or request-chosen value
// supplies OCI acquisition, local asset possession or minimal runtime authority.
func minimalLaunchTemplateIdentity(runtime RuntimeTarget) ([]sandboxruntime.MinimalLaunchTemplateIdentity, error) {
	var lock *sandboxruntime.RuntimeTemplateLockMetadata
	if runtime.Metadata != nil {
		lock = runtime.Metadata.TemplateLock
	}
	if runtime.Image == "" && lock == nil {
		return nil, nil // Existing omitted-template compatibility, not authority.
	}
	if lock == nil {
		return nil, errMinimalLaunchState
	}
	for _, role := range []struct {
		entry        *sandboxruntime.RuntimeTemplateLockEntryMetadata
		source, kind string
	}{
		{lock.Document, "oci_artifact", "oci_artifact"},
		{lock.TemplateReference, "template_reference", "oci_artifact"},
		{lock.RuntimeImage, "runtime_image", "oci_image"},
	} {
		if role.entry == nil || role.entry.SourceKind != role.source || role.entry.ReferenceKind != role.kind || role.entry.Status != "locked" || role.entry.DigestAlgorithm != "sha256" {
			return nil, errMinimalLaunchState
		}
	}
	value := sandboxruntime.MinimalLaunchTemplateIdentity{RuntimeImage: runtime.Image, TemplateDocumentSHA256: lock.Document.DigestValue,
		TemplateManifestSHA256: lock.TemplateReference.DigestValue, RuntimeImageSHA256: lock.RuntimeImage.DigestValue}
	if !sandboxruntime.ValidMinimalLaunchTemplateIdentity(value) {
		return nil, errMinimalLaunchState
	}
	return []sandboxruntime.MinimalLaunchTemplateIdentity{value}, nil
}
