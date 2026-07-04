package acquisition_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxtemplate"
	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition"
)

func TestEvaluateTrustPolicyStrictRejectsUnresolvedRequiredReferences(t *testing.T) {
	tmpl := trustPolicyTemplateWithRequiredReferences(false)
	lock := trustPolicyDocumentLock()
	for _, requirement := range trustPolicyAllRequiredReferences() {
		lock.References = append(lock.References, acquisition.ReferenceLock{
			Field:      requirement.Field,
			Kind:       requirement.Kind,
			Status:     acquisition.LockStatusUnresolved,
			ReasonCode: acquisition.LockReasonMutableReference,
		})
	}

	result := acquisition.EvaluateTrustPolicy(tmpl, acquisition.TrustPolicyRequest{
		Mode:               acquisition.TrustPolicyModeStrict,
		RequiredReferences: trustPolicyAllRequiredReferences(),
		Lock:               &lock,
	})

	if result.Decision != acquisition.TrustPolicyDecisionRejected {
		t.Fatalf("decision = %q, want rejected: %#v", result.Decision, result)
	}
	if len(result.Errors) != len(trustPolicyAllRequiredReferences()) {
		t.Fatalf("errors = %#v, want one unresolved error for each required reference", result.Errors)
	}
	for _, requirement := range trustPolicyAllRequiredReferences() {
		err := requireTrustPolicyError(t, result, requirement.Field)
		if err.Code != acquisition.TrustPolicyErrorUnresolvedLockEntry {
			t.Fatalf("%s code = %q, want unresolved_lock_entry", requirement.Field, err.Code)
		}
		if err.Field != "requiredReferences" {
			t.Fatalf("%s field = %q, want requiredReferences", requirement.Field, err.Field)
		}
		if err.ReasonCode != acquisition.LockReasonMutableReference {
			t.Fatalf("%s reason = %q, want mutable_reference", requirement.Field, err.ReasonCode)
		}
		if err.ReferenceIndex == nil {
			t.Fatalf("%s reference index = nil, want stable index", requirement.Field)
		}
	}
	assertTrustPolicyResultOmitsFragments(t, result, "token=", "sk-live-template", "ghcr.io/acme/go-agent:latest", "github.com/acme/repo")
}

func TestEvaluateTrustPolicyStrictRejectsMissingDigestPinWithoutLockOrProvenance(t *testing.T) {
	tmpl := trustPolicyTemplateWithRequiredReferences(false)
	lock := trustPolicyDocumentLock()

	result := acquisition.EvaluateTrustPolicy(tmpl, acquisition.TrustPolicyRequest{
		Mode: acquisition.TrustPolicyModeStrict,
		RequiredReferences: []acquisition.TrustPolicyReferenceRequirement{
			{Field: "runtime.image", Kind: sandboxtemplate.ReferenceKindOCIImage},
		},
		Lock: &lock,
	})

	if result.Decision != acquisition.TrustPolicyDecisionRejected {
		t.Fatalf("decision = %q, want rejected: %#v", result.Decision, result)
	}
	if len(result.Errors) != 1 {
		t.Fatalf("errors = %#v, want one missing digest pin error", result.Errors)
	}
	err := result.Errors[0]
	if err.Code != acquisition.TrustPolicyErrorMissingDigestPin {
		t.Fatalf("code = %q, want missing_digest_pin", err.Code)
	}
	if err.Field != "requiredReferences" || err.ReferenceField != "runtime.image" {
		t.Fatalf("error field/reference = %q/%q, want requiredReferences/runtime.image", err.Field, err.ReferenceField)
	}
	if err.ReasonCode != acquisition.LockReasonMutableReference {
		t.Fatalf("reason = %q, want mutable_reference", err.ReasonCode)
	}
	assertTrustPolicyResultOmitsFragments(t, result, "ghcr.io/acme/go-agent:latest")
}

func TestEvaluateTrustPolicyStrictRejectsMissingTemplateDocumentIdentity(t *testing.T) {
	tmpl := trustPolicyTemplateWithRequiredReferences(true)

	result := acquisition.EvaluateTrustPolicy(tmpl, acquisition.TrustPolicyRequest{
		Mode:               acquisition.TrustPolicyModeStrict,
		RequiredReferences: trustPolicyAllRequiredReferences(),
	})

	if result.Decision != acquisition.TrustPolicyDecisionRejected {
		t.Fatalf("decision = %q, want rejected: %#v", result.Decision, result)
	}
	if len(result.Errors) != 1 {
		t.Fatalf("errors = %#v, want one document identity error", result.Errors)
	}
	err := result.Errors[0]
	if err.Code != acquisition.TrustPolicyErrorMissingDigestPin {
		t.Fatalf("code = %q, want missing_digest_pin", err.Code)
	}
	if err.Field != "lock.document" {
		t.Fatalf("field = %q, want lock.document", err.Field)
	}
	if err.ReasonCode != acquisition.LockReasonDocumentDigest {
		t.Fatalf("reason = %q, want document_digest", err.ReasonCode)
	}
}

func TestEvaluateTrustPolicyStrictTrustsDigestPinnedLockAndProvenanceEvidence(t *testing.T) {
	tmpl := trustPolicyTemplateWithRequiredReferences(false)
	lock := trustPolicyDocumentLock()
	lock.References = []acquisition.ReferenceLock{
		trustPolicyReferenceLock("metadata.reference", sandboxtemplate.ReferenceKindOCIArtifact, "b"),
		trustPolicyReferenceLock("runtime.launch.descriptorRef", sandboxtemplate.ReferenceKindOCIArtifact, "d"),
		trustPolicyReferenceLock("workspace.ref", sandboxtemplate.ReferenceKindGit, "e"),
		trustPolicyReferenceLock("network.policySnapshotReference", sandboxtemplate.ReferenceKindOCIArtifact, "f"),
	}
	provenance := acquisition.TemplateLock{
		References: []acquisition.ReferenceLock{
			trustPolicyReferenceLock("runtime.image", sandboxtemplate.ReferenceKindOCIImage, "c"),
		},
	}

	result := acquisition.EvaluateTrustPolicy(tmpl, acquisition.TrustPolicyRequest{
		Mode:               acquisition.TrustPolicyModeStrict,
		RequiredReferences: trustPolicyAllRequiredReferences(),
		Lock:               &lock,
		Provenance:         &provenance,
	})

	if result.Decision != acquisition.TrustPolicyDecisionTrusted {
		t.Fatalf("decision = %q, want trusted: %#v", result.Decision, result)
	}
	if len(result.Errors) != 0 || len(result.Warnings) != 0 {
		t.Fatalf("policy findings = errors %#v warnings %#v, want none", result.Errors, result.Warnings)
	}
}

func TestEvaluateTrustPolicyAdvisoryReportsWarningsWithoutRejecting(t *testing.T) {
	tmpl := trustPolicyTemplateWithRequiredReferences(false)
	lock := trustPolicyDocumentLock()

	result := acquisition.EvaluateTrustPolicy(tmpl, acquisition.TrustPolicyRequest{
		Mode: acquisition.TrustPolicyModeAdvisory,
		RequiredReferences: []acquisition.TrustPolicyReferenceRequirement{
			{Field: "runtime.image", Kind: sandboxtemplate.ReferenceKindOCIImage},
		},
		Lock: &lock,
	})

	if result.Decision != acquisition.TrustPolicyDecisionAdvisory {
		t.Fatalf("decision = %q, want advisory: %#v", result.Decision, result)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("errors = %#v, want advisory warnings only", result.Errors)
	}
	if len(result.Warnings) != 1 {
		t.Fatalf("warnings = %#v, want one missing digest warning", result.Warnings)
	}
	if warning := result.Warnings[0]; warning.Code != acquisition.TrustPolicyWarningMissingDigestPin || warning.ReferenceField != "runtime.image" {
		t.Fatalf("warning = %#v, want missing runtime.image digest warning", warning)
	}
	assertTrustPolicyResultOmitsFragments(t, result, "ghcr.io/acme/go-agent:latest")
}

func trustPolicyTemplateWithRequiredReferences(pinned bool) sandboxtemplate.Template {
	return sandboxtemplate.Template{
		APIVersion: sandboxtemplate.TemplateAPIVersionV1,
		Kind:       sandboxtemplate.TemplateKindSandbox,
		Metadata: sandboxtemplate.TemplateMetadata{
			ID:        "codex-go",
			Reference: trustPolicyRef(sandboxtemplate.ReferenceKindOCIArtifact, "ghcr.io/acme/templates/codex-go:latest", pinned, "b"),
		},
		Runtime: &sandboxtemplate.RuntimeRequirements{
			Driver: sandboxtemplate.RuntimeDriverMicroVM,
			Image:  trustPolicyRef(sandboxtemplate.ReferenceKindOCIImage, "ghcr.io/acme/go-agent:latest", pinned, "c"),
			Launch: &sandboxtemplate.LaunchRequirements{
				DescriptorRef: trustPolicyRef(sandboxtemplate.ReferenceKindOCIArtifact, "ghcr.io/acme/launch:latest", pinned, "d"),
			},
		},
		Workspace: &sandboxtemplate.WorkspaceRequirements{
			Mode:        sandboxtemplate.WorkspaceModeClone,
			InputSource: sandboxtemplate.WorkspaceInputRemoteRef,
			Ref:         trustPolicyRef(sandboxtemplate.ReferenceKindGit, "github.com/acme/repo", pinned, "e"),
		},
		Network: &sandboxtemplate.NetworkRequirements{
			Profile:                 sandboxtemplate.NetworkProfileDenyByDefault,
			PolicySnapshotReference: trustPolicyRef(sandboxtemplate.ReferenceKindOCIArtifact, "ghcr.io/acme/policies/default:latest?token=sk-live-template", pinned, "f"),
		},
	}
}

func trustPolicyRef(kind sandboxtemplate.ReferenceKind, value string, pinned bool, digestSeed string) *sandboxtemplate.ImmutableRef {
	ref := &sandboxtemplate.ImmutableRef{Kind: kind, Ref: value}
	if pinned {
		ref.Digest = testDigest(strings.Repeat(digestSeed, 64))
	}
	return ref
}

func trustPolicyAllRequiredReferences() []acquisition.TrustPolicyReferenceRequirement {
	return []acquisition.TrustPolicyReferenceRequirement{
		{Field: "metadata.reference", Kind: sandboxtemplate.ReferenceKindOCIArtifact},
		{Field: "runtime.image", Kind: sandboxtemplate.ReferenceKindOCIImage},
		{Field: "runtime.launch.descriptorRef", Kind: sandboxtemplate.ReferenceKindOCIArtifact},
		{Field: "workspace.ref", Kind: sandboxtemplate.ReferenceKindGit},
		{Field: "network.policySnapshotReference", Kind: sandboxtemplate.ReferenceKindOCIArtifact},
	}
}

func trustPolicyDocumentLock() acquisition.TemplateLock {
	return acquisition.TemplateLock{
		SourceKind:    acquisition.SourceKindLocalFile,
		ReferenceKind: sandboxtemplate.ReferenceKindLocal,
		Status:        acquisition.LockStatusLocked,
		Document: acquisition.DigestLock{
			Status:     acquisition.LockStatusLocked,
			Digest:     testDigest(strings.Repeat("a", 64)),
			ReasonCode: acquisition.LockReasonDocumentDigest,
		},
	}
}

func trustPolicyReferenceLock(field string, kind sandboxtemplate.ReferenceKind, digestSeed string) acquisition.ReferenceLock {
	return acquisition.ReferenceLock{
		Field:      field,
		Kind:       kind,
		Status:     acquisition.LockStatusLocked,
		Digest:     testDigest(strings.Repeat(digestSeed, 64)),
		ReasonCode: acquisition.LockReasonImmutableDigest,
	}
}

func requireTrustPolicyError(t *testing.T, result acquisition.TrustPolicyResult, referenceField string) acquisition.TrustPolicyError {
	t.Helper()
	for _, err := range result.Errors {
		if err.ReferenceField == referenceField {
			return err
		}
	}
	t.Fatalf("errors = %#v, missing reference field %s", result.Errors, referenceField)
	return acquisition.TrustPolicyError{}
}

func assertTrustPolicyResultOmitsFragments(t *testing.T, result acquisition.TrustPolicyResult, fragments ...string) {
	t.Helper()
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal(result) error = %v", err)
	}
	assertAcquisitionTextOmitsFragments(t, string(data), fragments...)
}
