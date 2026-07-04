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
	tmpl := trustPolicyTemplateWithRequiredReferences(true)
	lock := trustPolicyDocumentLock()
	provenance := trustPolicyDocumentLock()

	result := acquisition.EvaluateTrustPolicy(tmpl, acquisition.TrustPolicyRequest{
		Mode: acquisition.TrustPolicyModeStrict,
		RequiredReferences: []acquisition.TrustPolicyReferenceRequirement{
			{Field: "runtime.image", Kind: sandboxtemplate.ReferenceKindOCIImage},
		},
		Lock:       &lock,
		Provenance: &provenance,
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

func TestEvaluateTrustPolicyDefaultModeIsStrictProductionRejection(t *testing.T) {
	tmpl := trustPolicyTemplateWithRequiredReferences(false)
	lock := trustPolicyDocumentLock()
	provenance := trustPolicyDocumentLock()

	result := acquisition.EvaluateTrustPolicy(tmpl, acquisition.TrustPolicyRequest{
		RequiredReferences: []acquisition.TrustPolicyReferenceRequirement{
			{Field: "runtime.image", Kind: sandboxtemplate.ReferenceKindOCIImage},
		},
		Lock:       &lock,
		Provenance: &provenance,
	})

	if result.Mode != acquisition.TrustPolicyModeStrict {
		t.Fatalf("mode = %q, want default strict mode", result.Mode)
	}
	if result.Decision != acquisition.TrustPolicyDecisionRejected {
		t.Fatalf("decision = %q, want rejected by default: %#v", result.Decision, result)
	}
	if result.Enforcement == nil || !result.Enforcement.StrictlyEnforced {
		t.Fatalf("enforcement = %#v, want strict enforcement metadata", result.Enforcement)
	}
	if len(result.Errors) != 1 || len(result.Warnings) != 0 {
		t.Fatalf("findings = errors %#v warnings %#v, want strict error only", result.Errors, result.Warnings)
	}
}

func TestEvaluateTrustPolicyStrictRejectsEveryRolloutPolicyCode(t *testing.T) {
	for _, tt := range trustPolicyRolloutFindingCases() {
		t.Run(tt.name, func(t *testing.T) {
			tmpl, request := tt.buildRequest()
			request.Mode = acquisition.TrustPolicyModeStrict

			result := acquisition.EvaluateTrustPolicy(tmpl, request)

			if result.Decision != acquisition.TrustPolicyDecisionRejected {
				t.Fatalf("decision = %q, want rejected: %#v", result.Decision, result)
			}
			if len(result.Errors) != 1 || len(result.Warnings) != 0 {
				t.Fatalf("findings = errors %#v warnings %#v, want one strict error", result.Errors, result.Warnings)
			}
			err := result.Errors[0]
			if err.Code != tt.wantError {
				t.Fatalf("error code = %q, want %q: %#v", err.Code, tt.wantError, result)
			}
			if err.Field != tt.wantField {
				t.Fatalf("error field = %q, want %q: %#v", err.Field, tt.wantField, err)
			}
			if err.ReferenceField != tt.wantReferenceField {
				t.Fatalf("reference field = %q, want %q: %#v", err.ReferenceField, tt.wantReferenceField, err)
			}
			if err.ReasonCode != tt.wantReason {
				t.Fatalf("reason = %q, want %q: %#v", err.ReasonCode, tt.wantReason, err)
			}
			assertTrustPolicyResultOmitsFragments(t, result,
				"/Users/v/private-template.yaml",
				"ghcr.io/acme/go-agent:latest",
				"github.com/acme/repo",
				"token=",
				"sk-live-template",
				"fixture-user",
				"registry.invalid",
				"https://",
			)
		})
	}
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

func TestEvaluateTrustPolicyStrictTrustsMatchingLockAndProvenanceEvidence(t *testing.T) {
	tmpl := trustPolicyTemplateWithRequiredReferences(true)
	lock := trustPolicyDocumentLock()
	lock.References = []acquisition.ReferenceLock{
		trustPolicyReferenceLock("metadata.reference", sandboxtemplate.ReferenceKindOCIArtifact, "b"),
		trustPolicyReferenceLock("runtime.image", sandboxtemplate.ReferenceKindOCIImage, "c"),
		trustPolicyReferenceLock("runtime.launch.descriptorRef", sandboxtemplate.ReferenceKindOCIArtifact, "d"),
		trustPolicyReferenceLock("workspace.ref", sandboxtemplate.ReferenceKindGit, "e"),
		trustPolicyReferenceLock("network.policySnapshotReference", sandboxtemplate.ReferenceKindOCIArtifact, "f"),
	}
	provenance := trustPolicyDocumentLock()
	provenance.References = []acquisition.ReferenceLock{
		trustPolicyReferenceLock("metadata.reference", sandboxtemplate.ReferenceKindOCIArtifact, "b"),
		trustPolicyReferenceLock("runtime.image", sandboxtemplate.ReferenceKindOCIImage, "c"),
		trustPolicyReferenceLock("runtime.launch.descriptorRef", sandboxtemplate.ReferenceKindOCIArtifact, "d"),
		trustPolicyReferenceLock("workspace.ref", sandboxtemplate.ReferenceKindGit, "e"),
		trustPolicyReferenceLock("network.policySnapshotReference", sandboxtemplate.ReferenceKindOCIArtifact, "f"),
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

func TestEvaluateTrustPolicyStrictRejectsLockWithoutMatchingProvenanceEvidence(t *testing.T) {
	tmpl := trustPolicyMinimalTemplate()
	lock := trustPolicyDocumentLock()

	result := acquisition.EvaluateTrustPolicy(tmpl, acquisition.TrustPolicyRequest{
		Mode: acquisition.TrustPolicyModeStrict,
		Lock: &lock,
	})

	if result.Decision != acquisition.TrustPolicyDecisionRejected {
		t.Fatalf("decision = %q, want rejected: %#v", result.Decision, result)
	}
	if len(result.Errors) != 1 {
		t.Fatalf("errors = %#v, want one provenance evidence error", result.Errors)
	}
	err := result.Errors[0]
	if err.Code != acquisition.TrustPolicyErrorLockProvenanceMismatch {
		t.Fatalf("code = %q, want lock_provenance_mismatch", err.Code)
	}
	if err.Field != "lock.document" || err.ReasonCode != acquisition.LockReasonDocumentDigest {
		t.Fatalf("error = %#v, want document provenance mismatch", err)
	}
	assertTrustPolicyResultOmitsFragments(t, result, "/Users/v/private-template.yaml", "token=", "sk-live-template")
}

func TestEvaluateTrustPolicyStrictRejectsMissingRequiredLockEntryEvenWithProvenance(t *testing.T) {
	tmpl := trustPolicyTemplateWithRequiredReferences(false)
	lock := trustPolicyDocumentLock()
	provenance := trustPolicyDocumentLock()
	provenance.References = []acquisition.ReferenceLock{
		trustPolicyReferenceLock("runtime.image", sandboxtemplate.ReferenceKindOCIImage, "c"),
	}

	result := acquisition.EvaluateTrustPolicy(tmpl, acquisition.TrustPolicyRequest{
		Mode: acquisition.TrustPolicyModeStrict,
		RequiredReferences: []acquisition.TrustPolicyReferenceRequirement{
			{Field: "runtime.image", Kind: sandboxtemplate.ReferenceKindOCIImage},
		},
		Lock:       &lock,
		Provenance: &provenance,
	})

	if result.Decision != acquisition.TrustPolicyDecisionRejected {
		t.Fatalf("decision = %q, want rejected: %#v", result.Decision, result)
	}
	if len(result.Errors) != 1 {
		t.Fatalf("errors = %#v, want one missing lock entry error", result.Errors)
	}
	err := result.Errors[0]
	if err.Code != acquisition.TrustPolicyErrorMutableReference {
		t.Fatalf("code = %q, want mutable_reference", err.Code)
	}
	if err.Field != "requiredReferences" || err.ReferenceField != "runtime.image" {
		t.Fatalf("error field/reference = %q/%q, want requiredReferences/runtime.image", err.Field, err.ReferenceField)
	}
	if err.ReferenceIndex == nil || *err.ReferenceIndex != 0 {
		t.Fatalf("reference index = %#v, want 0", err.ReferenceIndex)
	}
	if err.ReasonCode != acquisition.LockReasonMutableReference {
		t.Fatalf("reason = %q, want mutable_reference", err.ReasonCode)
	}
	assertTrustPolicyResultOmitsFragments(t, result, "ghcr.io/acme/go-agent:latest", "token=", "registryAuth")
}

func TestEvaluateTrustPolicyStrictRejectsProvenanceDigestMismatch(t *testing.T) {
	tmpl := trustPolicyTemplateWithRequiredReferences(true)
	tmpl.Runtime.Image.Ref = "ghcr.io/acme/go-agent:latest?token=sk-live-template"
	lock := trustPolicyDocumentLock()
	lock.References = []acquisition.ReferenceLock{
		trustPolicyReferenceLock("runtime.image", sandboxtemplate.ReferenceKindOCIImage, "c"),
	}
	provenance := trustPolicyDocumentLock()
	provenance.References = []acquisition.ReferenceLock{
		trustPolicyReferenceLock("runtime.image", sandboxtemplate.ReferenceKindOCIImage, "d"),
	}

	result := acquisition.EvaluateTrustPolicy(tmpl, acquisition.TrustPolicyRequest{
		Mode: acquisition.TrustPolicyModeStrict,
		RequiredReferences: []acquisition.TrustPolicyReferenceRequirement{
			{Field: "runtime.image", Kind: sandboxtemplate.ReferenceKindOCIImage},
		},
		Lock:       &lock,
		Provenance: &provenance,
	})

	if result.Decision != acquisition.TrustPolicyDecisionRejected {
		t.Fatalf("decision = %q, want rejected: %#v", result.Decision, result)
	}
	if len(result.Errors) != 1 {
		t.Fatalf("errors = %#v, want one lock/provenance mismatch", result.Errors)
	}
	err := result.Errors[0]
	if err.Code != acquisition.TrustPolicyErrorLockProvenanceMismatch {
		t.Fatalf("code = %q, want lock_provenance_mismatch", err.Code)
	}
	if err.Field != "requiredReferences" || err.ReferenceField != "runtime.image" {
		t.Fatalf("error field/reference = %q/%q, want requiredReferences/runtime.image", err.Field, err.ReferenceField)
	}
	if err.ReferenceIndex == nil || *err.ReferenceIndex != 0 {
		t.Fatalf("reference index = %#v, want 0", err.ReferenceIndex)
	}
	if err.ReasonCode != acquisition.LockReasonImmutableDigest {
		t.Fatalf("reason = %q, want immutable_digest", err.ReasonCode)
	}
	assertTrustPolicyResultOmitsFragments(t, result,
		"/Users/v/private-template.yaml",
		"ghcr.io/acme/go-agent:latest",
		"token=",
		"sk-live-template",
		"registryAuth",
		"authorization",
		"user:password",
	)
}

func TestEvaluateTrustPolicyAdvisoryReportsWarningsWithoutRejecting(t *testing.T) {
	tmpl := trustPolicyTemplateWithRequiredReferences(false)
	lock := trustPolicyDocumentLock()
	provenance := trustPolicyDocumentLock()

	result := acquisition.EvaluateTrustPolicy(tmpl, acquisition.TrustPolicyRequest{
		Mode: acquisition.TrustPolicyModeAdvisory,
		RequiredReferences: []acquisition.TrustPolicyReferenceRequirement{
			{Field: "runtime.image", Kind: sandboxtemplate.ReferenceKindOCIImage},
		},
		Lock:       &lock,
		Provenance: &provenance,
	})

	if result.Decision != acquisition.TrustPolicyDecisionAdvisory {
		t.Fatalf("decision = %q, want advisory: %#v", result.Decision, result)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("errors = %#v, want advisory warnings only", result.Errors)
	}
	if len(result.Warnings) != 1 {
		t.Fatalf("warnings = %#v, want one mutable reference warning", result.Warnings)
	}
	if result.Enforcement == nil || result.Enforcement.StrictlyEnforced {
		t.Fatalf("enforcement = %#v, want advisory metadata showing strict enforcement disabled", result.Enforcement)
	}
	if warning := result.Warnings[0]; warning.Code != acquisition.TrustPolicyWarningMutableReference || warning.ReferenceField != "runtime.image" || warning.ReasonCode != acquisition.LockReasonMutableReference {
		t.Fatalf("warning = %#v, want mutable runtime.image warning with reason code", warning)
	}
	assertTrustPolicyResultOmitsFragments(t, result, "ghcr.io/acme/go-agent:latest")
}

func TestEvaluateTrustPolicyAdvisoryReportsEveryRolloutWarningWithoutTrustedDecision(t *testing.T) {
	for _, tt := range trustPolicyRolloutFindingCases() {
		t.Run(tt.name, func(t *testing.T) {
			tmpl, request := tt.buildRequest()
			request.Mode = acquisition.TrustPolicyModeAdvisory

			result := acquisition.EvaluateTrustPolicy(tmpl, request)

			if result.Decision != acquisition.TrustPolicyDecisionAdvisory {
				t.Fatalf("decision = %q, want advisory instead of trusted: %#v", result.Decision, result)
			}
			if len(result.Errors) != 0 || len(result.Warnings) != 1 {
				t.Fatalf("findings = errors %#v warnings %#v, want one advisory warning", result.Errors, result.Warnings)
			}
			warning := result.Warnings[0]
			if warning.Code != tt.wantWarning {
				t.Fatalf("warning code = %q, want %q: %#v", warning.Code, tt.wantWarning, result)
			}
			if warning.Field != tt.wantField {
				t.Fatalf("warning field = %q, want %q: %#v", warning.Field, tt.wantField, warning)
			}
			if warning.ReferenceField != tt.wantReferenceField {
				t.Fatalf("reference field = %q, want %q: %#v", warning.ReferenceField, tt.wantReferenceField, warning)
			}
			if warning.ReasonCode != tt.wantReason {
				t.Fatalf("reason = %q, want %q: %#v", warning.ReasonCode, tt.wantReason, warning)
			}
			assertTrustPolicyResultOmitsFragments(t, result,
				"/Users/v/private-template.yaml",
				"ghcr.io/acme/go-agent:latest",
				"github.com/acme/repo",
				"token=",
				"sk-live-template",
				"fixture-user",
				"registry.invalid",
				"https://",
			)
		})
	}
}

func TestEvaluateTrustPolicyAdvisoryWithMatchingEvidenceDoesNotClaimTrusted(t *testing.T) {
	tmpl := trustPolicyTemplateWithRequiredReferences(true)
	lock := trustPolicyDocumentLock()
	lock.References = []acquisition.ReferenceLock{
		trustPolicyReferenceLock("metadata.reference", sandboxtemplate.ReferenceKindOCIArtifact, "b"),
		trustPolicyReferenceLock("runtime.image", sandboxtemplate.ReferenceKindOCIImage, "c"),
		trustPolicyReferenceLock("runtime.launch.descriptorRef", sandboxtemplate.ReferenceKindOCIArtifact, "d"),
		trustPolicyReferenceLock("workspace.ref", sandboxtemplate.ReferenceKindGit, "e"),
		trustPolicyReferenceLock("network.policySnapshotReference", sandboxtemplate.ReferenceKindOCIArtifact, "f"),
	}
	provenance := trustPolicyDocumentLock()
	provenance.References = []acquisition.ReferenceLock{
		trustPolicyReferenceLock("metadata.reference", sandboxtemplate.ReferenceKindOCIArtifact, "b"),
		trustPolicyReferenceLock("runtime.image", sandboxtemplate.ReferenceKindOCIImage, "c"),
		trustPolicyReferenceLock("runtime.launch.descriptorRef", sandboxtemplate.ReferenceKindOCIArtifact, "d"),
		trustPolicyReferenceLock("workspace.ref", sandboxtemplate.ReferenceKindGit, "e"),
		trustPolicyReferenceLock("network.policySnapshotReference", sandboxtemplate.ReferenceKindOCIArtifact, "f"),
	}

	result := acquisition.EvaluateTrustPolicy(tmpl, acquisition.TrustPolicyRequest{
		Mode:               acquisition.TrustPolicyModeAdvisory,
		RequiredReferences: trustPolicyAllRequiredReferences(),
		Lock:               &lock,
		Provenance:         &provenance,
	})

	if result.Decision != acquisition.TrustPolicyDecisionAdvisory {
		t.Fatalf("decision = %q, want advisory despite matching evidence: %#v", result.Decision, result)
	}
	if len(result.Errors) != 0 || len(result.Warnings) != 0 {
		t.Fatalf("findings = errors %#v warnings %#v, want no findings in advisory label", result.Errors, result.Warnings)
	}
	if result.Enforcement == nil || result.Enforcement.StrictlyEnforced {
		t.Fatalf("enforcement = %#v, want advisory mode to keep strict enforcement disabled", result.Enforcement)
	}
}

func TestEvaluateTrustPolicyAdvisoryReportsMutableAndUnresolvedWarningCodes(t *testing.T) {
	tmpl := trustPolicyTemplateWithRequiredReferences(false)
	lock := trustPolicyDocumentLock()
	provenance := trustPolicyDocumentLock()
	lock.References = []acquisition.ReferenceLock{{
		Field:      "workspace.ref",
		Kind:       sandboxtemplate.ReferenceKindGit,
		Status:     acquisition.LockStatusUnresolved,
		ReasonCode: acquisition.LockReasonMutableReference,
	}}

	result := acquisition.EvaluateTrustPolicy(tmpl, acquisition.TrustPolicyRequest{
		Mode: acquisition.TrustPolicyModeAdvisory,
		RequiredReferences: []acquisition.TrustPolicyReferenceRequirement{
			{Field: "runtime.image", Kind: sandboxtemplate.ReferenceKindOCIImage},
			{Field: "workspace.ref", Kind: sandboxtemplate.ReferenceKindGit},
		},
		Lock:       &lock,
		Provenance: &provenance,
	})

	if result.Decision != acquisition.TrustPolicyDecisionAdvisory {
		t.Fatalf("decision = %q, want advisory: %#v", result.Decision, result)
	}
	if len(result.Errors) != 0 || len(result.Warnings) != 2 {
		t.Fatalf("findings = errors %#v warnings %#v, want two advisory warnings only", result.Errors, result.Warnings)
	}
	mutable := requireTrustPolicyWarning(t, result, "runtime.image")
	if mutable.Code != acquisition.TrustPolicyWarningMutableReference || mutable.ReasonCode != acquisition.LockReasonMutableReference {
		t.Fatalf("mutable warning = %#v, want mutable_reference code and reason", mutable)
	}
	unresolved := requireTrustPolicyWarning(t, result, "workspace.ref")
	if unresolved.Code != acquisition.TrustPolicyWarningUnresolvedLockEntry || unresolved.ReasonCode != acquisition.LockReasonMutableReference {
		t.Fatalf("unresolved warning = %#v, want unresolved_lock_entry code with mutable_reference reason", unresolved)
	}
}

type trustPolicyRolloutFindingCase struct {
	name               string
	buildRequest       func() (sandboxtemplate.Template, acquisition.TrustPolicyRequest)
	wantError          acquisition.TrustPolicyErrorCode
	wantWarning        acquisition.TrustPolicyWarningCode
	wantField          string
	wantReferenceField string
	wantReason         acquisition.LockReasonCode
}

func trustPolicyRolloutFindingCases() []trustPolicyRolloutFindingCase {
	return []trustPolicyRolloutFindingCase{
		{
			name: "mutable reference",
			buildRequest: func() (sandboxtemplate.Template, acquisition.TrustPolicyRequest) {
				tmpl := trustPolicyTemplateWithRequiredReferences(false)
				lock := trustPolicyDocumentLock()
				provenance := trustPolicyDocumentLock()
				return tmpl, acquisition.TrustPolicyRequest{
					RequiredReferences: []acquisition.TrustPolicyReferenceRequirement{
						{Field: "runtime.image", Kind: sandboxtemplate.ReferenceKindOCIImage},
					},
					Lock:       &lock,
					Provenance: &provenance,
				}
			},
			wantError:          acquisition.TrustPolicyErrorMutableReference,
			wantWarning:        acquisition.TrustPolicyWarningMutableReference,
			wantField:          "requiredReferences",
			wantReferenceField: "runtime.image",
			wantReason:         acquisition.LockReasonMutableReference,
		},
		{
			name: "missing digest pin",
			buildRequest: func() (sandboxtemplate.Template, acquisition.TrustPolicyRequest) {
				tmpl := trustPolicyTemplateWithRequiredReferences(true)
				lock := trustPolicyDocumentLock()
				lock.References = []acquisition.ReferenceLock{{
					Field:      "runtime.image",
					Kind:       sandboxtemplate.ReferenceKindOCIImage,
					Status:     acquisition.LockStatusLocked,
					ReasonCode: acquisition.LockReasonImmutableDigest,
				}}
				provenance := trustPolicyDocumentLock()
				provenance.References = []acquisition.ReferenceLock{{
					Field:      "runtime.image",
					Kind:       sandboxtemplate.ReferenceKindOCIImage,
					Status:     acquisition.LockStatusLocked,
					ReasonCode: acquisition.LockReasonImmutableDigest,
				}}
				return tmpl, acquisition.TrustPolicyRequest{
					RequiredReferences: []acquisition.TrustPolicyReferenceRequirement{
						{Field: "runtime.image", Kind: sandboxtemplate.ReferenceKindOCIImage},
					},
					Lock:       &lock,
					Provenance: &provenance,
				}
			},
			wantError:          acquisition.TrustPolicyErrorMissingDigestPin,
			wantWarning:        acquisition.TrustPolicyWarningMissingDigestPin,
			wantField:          "requiredReferences",
			wantReferenceField: "runtime.image",
			wantReason:         acquisition.LockReasonImmutableDigest,
		},
		{
			name: "unresolved lock entry",
			buildRequest: func() (sandboxtemplate.Template, acquisition.TrustPolicyRequest) {
				tmpl := trustPolicyTemplateWithRequiredReferences(true)
				lock := trustPolicyDocumentLock()
				lock.References = []acquisition.ReferenceLock{{
					Field:      "runtime.image",
					Kind:       sandboxtemplate.ReferenceKindOCIImage,
					Status:     acquisition.LockStatusUnresolved,
					ReasonCode: acquisition.LockReasonMutableReference,
				}}
				provenance := trustPolicyDocumentLock()
				provenance.References = []acquisition.ReferenceLock{
					trustPolicyReferenceLock("runtime.image", sandboxtemplate.ReferenceKindOCIImage, "c"),
				}
				return tmpl, acquisition.TrustPolicyRequest{
					RequiredReferences: []acquisition.TrustPolicyReferenceRequirement{
						{Field: "runtime.image", Kind: sandboxtemplate.ReferenceKindOCIImage},
					},
					Lock:       &lock,
					Provenance: &provenance,
				}
			},
			wantError:          acquisition.TrustPolicyErrorUnresolvedLockEntry,
			wantWarning:        acquisition.TrustPolicyWarningUnresolvedLockEntry,
			wantField:          "requiredReferences",
			wantReferenceField: "runtime.image",
			wantReason:         acquisition.LockReasonMutableReference,
		},
		{
			name: "lock provenance mismatch",
			buildRequest: func() (sandboxtemplate.Template, acquisition.TrustPolicyRequest) {
				tmpl := trustPolicyTemplateWithRequiredReferences(true)
				lock := trustPolicyDocumentLock()
				lock.References = []acquisition.ReferenceLock{
					trustPolicyReferenceLock("runtime.image", sandboxtemplate.ReferenceKindOCIImage, "c"),
				}
				provenance := trustPolicyDocumentLock()
				provenance.References = []acquisition.ReferenceLock{
					trustPolicyReferenceLock("runtime.image", sandboxtemplate.ReferenceKindOCIImage, "d"),
				}
				return tmpl, acquisition.TrustPolicyRequest{
					RequiredReferences: []acquisition.TrustPolicyReferenceRequirement{
						{Field: "runtime.image", Kind: sandboxtemplate.ReferenceKindOCIImage},
					},
					Lock:       &lock,
					Provenance: &provenance,
				}
			},
			wantError:          acquisition.TrustPolicyErrorLockProvenanceMismatch,
			wantWarning:        acquisition.TrustPolicyWarningLockProvenanceMismatch,
			wantField:          "requiredReferences",
			wantReferenceField: "runtime.image",
			wantReason:         acquisition.LockReasonImmutableDigest,
		},
		{
			name: "unsupported source",
			buildRequest: func() (sandboxtemplate.Template, acquisition.TrustPolicyRequest) {
				lock := trustPolicyUnresolvedDocumentLock(acquisition.SourceKindUnsupported, "", acquisition.LockReasonUnsupportedSource)
				lock.Warnings = []acquisition.LockReasonCode{acquisition.LockReasonUnsupportedSource}
				return trustPolicyMinimalTemplate(), acquisition.TrustPolicyRequest{Lock: &lock}
			},
			wantError:   acquisition.TrustPolicyErrorUnsupportedSource,
			wantWarning: acquisition.TrustPolicyWarningUnsupportedSource,
			wantField:   "lock.document",
			wantReason:  acquisition.LockReasonUnsupportedSource,
		},
		{
			name: "resolver unavailable",
			buildRequest: func() (sandboxtemplate.Template, acquisition.TrustPolicyRequest) {
				lock := trustPolicyUnresolvedDocumentLock(acquisition.SourceKindGit, sandboxtemplate.ReferenceKindGit, acquisition.LockReasonResolverUnavailable)
				return trustPolicyMinimalTemplate(), acquisition.TrustPolicyRequest{Lock: &lock}
			},
			wantError:   acquisition.TrustPolicyErrorResolverUnavailable,
			wantWarning: acquisition.TrustPolicyWarningResolverUnavailable,
			wantField:   "lock.document",
			wantReason:  acquisition.LockReasonResolverUnavailable,
		},
	}
}

func trustPolicyMinimalTemplate() sandboxtemplate.Template {
	return sandboxtemplate.Template{
		APIVersion: sandboxtemplate.TemplateAPIVersionV1,
		Kind:       sandboxtemplate.TemplateKindSandbox,
		Metadata: sandboxtemplate.TemplateMetadata{
			ID: "codex-go",
		},
	}
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

func trustPolicyUnresolvedDocumentLock(sourceKind acquisition.SourceKind, referenceKind sandboxtemplate.ReferenceKind, reason acquisition.LockReasonCode) acquisition.TemplateLock {
	return acquisition.TemplateLock{
		SourceKind:    sourceKind,
		ReferenceKind: referenceKind,
		Status:        acquisition.LockStatusUnresolved,
		Document: acquisition.DigestLock{
			Status:     acquisition.LockStatusUnresolved,
			ReasonCode: reason,
		},
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

func requireTrustPolicyWarning(t *testing.T, result acquisition.TrustPolicyResult, referenceField string) acquisition.TrustPolicyWarning {
	t.Helper()
	for _, warning := range result.Warnings {
		if warning.ReferenceField == referenceField {
			return warning
		}
	}
	t.Fatalf("warnings = %#v, missing reference field %s", result.Warnings, referenceField)
	return acquisition.TrustPolicyWarning{}
}

func assertTrustPolicyResultOmitsFragments(t *testing.T, result acquisition.TrustPolicyResult, fragments ...string) {
	t.Helper()
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal(result) error = %v", err)
	}
	assertAcquisitionTextOmitsFragments(t, string(data), fragments...)
}
