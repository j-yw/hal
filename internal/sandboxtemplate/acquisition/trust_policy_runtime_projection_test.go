package acquisition_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition"
)

func TestProjectRuntimeTemplateLockMetadataSurfacesSanitizedTrustPolicyOutcome(t *testing.T) {
	projection := &acquisition.TemplateProvenanceProjection{
		Document: &acquisition.TemplateProvenanceEntry{
			SourceKind:      "oci_artifact",
			ReferenceKind:   "oci_artifact",
			Status:          "locked",
			DigestAlgorithm: "sha256",
			DigestValue:     strings.Repeat("a", 64),
			WarningCodes: []string{
				"resolver_unavailable",
				"unsupported_source",
				"registry.invalid/acme/template:latest?token=ghp_fixturetoken",
			},
			ReasonCode: "document_digest",
		},
		RuntimeImage: &acquisition.TemplateProvenanceEntry{
			SourceKind:      "runtime_image",
			ReferenceKind:   "oci_image",
			Status:          "locked",
			DigestAlgorithm: "sha256",
			DigestValue:     strings.Repeat("b", 64),
			ReasonCode:      "runtime_image_digest",
		},
	}
	result := acquisition.TrustPolicyResult{
		Mode:     acquisition.TrustPolicyModeStrict,
		Decision: acquisition.TrustPolicyDecisionRejected,
		Errors: []acquisition.TrustPolicyError{{
			Code:       acquisition.TrustPolicyErrorLockProvenanceMismatch,
			ReasonCode: acquisition.LockReasonImmutableDigest,
			Message:    "should not leak ghcr.io/acme/go-agent:latest?token=ghp_fixturetoken",
		}},
		Warnings: []acquisition.TrustPolicyWarning{
			{
				Code:       acquisition.TrustPolicyWarningResolverUnavailable,
				ReasonCode: acquisition.LockReasonResolverUnavailable,
				Message:    "should not leak AWS_SECRET_ACCESS_KEY=sk-live-template",
			},
			{
				Code:       acquisition.TrustPolicyWarningCode("https://fixture-user:secret@registry.invalid"),
				ReasonCode: acquisition.LockReasonCode("/Users/v/private-template.yaml"),
			},
		},
	}

	lock := acquisition.ProjectRuntimeTemplateLockMetadata(projection, result)
	if lock == nil {
		t.Fatal("ProjectRuntimeTemplateLockMetadata() = nil, want runtime template lock metadata")
	}
	if lock.Document == nil || lock.RuntimeImage == nil {
		t.Fatalf("runtime lock = %#v, want projected document and runtime image entries", lock)
	}
	if lock.TrustPolicy == nil {
		t.Fatalf("runtime lock = %#v, want trustPolicy metadata", lock)
	}
	if got := lock.TrustPolicy.Mode; got != "strict" {
		t.Fatalf("trust policy mode = %q, want strict", got)
	}
	if got := lock.TrustPolicy.Decision; got != "rejected" {
		t.Fatalf("trust policy decision = %q, want rejected", got)
	}
	if got := lock.TrustPolicy.SourceKind; got != "oci_artifact" {
		t.Fatalf("trust policy source kind = %q, want oci_artifact", got)
	}
	if got := lock.TrustPolicy.Status; got != "locked" {
		t.Fatalf("trust policy status = %q, want locked", got)
	}
	if got := lock.TrustPolicy.DigestValue; got != strings.Repeat("a", 64) {
		t.Fatalf("trust policy digest = %q, want document digest", got)
	}
	if got, want := lock.TrustPolicy.ErrorCodes, []string{"lock_provenance_mismatch"}; !stringSlicesEqual(got, want) {
		t.Fatalf("trust policy error codes = %#v, want %#v", got, want)
	}
	if got, want := lock.TrustPolicy.WarningCodes, []string{"resolver_unavailable"}; !stringSlicesEqual(got, want) {
		t.Fatalf("trust policy warning codes = %#v, want %#v", got, want)
	}
	if got, want := lock.TrustPolicy.ReasonCodes, []string{"immutable_digest", "resolver_unavailable"}; !stringSlicesEqual(got, want) {
		t.Fatalf("trust policy reason codes = %#v, want %#v", got, want)
	}

	data, err := json.Marshal(lock)
	if err != nil {
		t.Fatalf("Marshal(runtime lock) error = %v", err)
	}
	assertAcquisitionTextOmitsFragments(t, string(data),
		"ghcr.io/acme/go-agent:latest",
		"registry.invalid",
		"fixture-user",
		"token=",
		"ghp_fixturetoken",
		"AWS_SECRET_ACCESS_KEY",
		"sk-live-template",
		"/Users/v",
		"private-template",
	)
}

func stringSlicesEqual(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
