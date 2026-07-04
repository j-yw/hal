package microvm

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestLiveE2ETemplateTrustMetadataContractFieldsAndJSONNames(t *testing.T) {
	metadataType := reflect.TypeOf(LiveE2ETemplateTrustMetadata{})
	assertConfigField(t, metadataType, "TemplateID", reflect.TypeOf(""), `json:"templateId,omitempty"`)
	assertConfigField(t, metadataType, "ProvenanceLabels", reflect.TypeOf([]string{}), `json:"provenanceLabels,omitempty"`)
	assertConfigField(t, metadataType, "TrustPolicyID", reflect.TypeOf(""), `json:"trustPolicyId,omitempty"`)
	assertConfigField(t, metadataType, "Status", reflect.TypeOf(""), `json:"status,omitempty"`)
	assertConfigField(t, metadataType, "ReasonCodes", reflect.TypeOf([]string{}), `json:"reasonCodes,omitempty"`)

	resultType := reflect.TypeOf(LiveE2ETemplateTrustProjectionResult{})
	assertConfigField(t, resultType, "Status", reflect.TypeOf(LiveE2EReadinessStatus("")), `json:"status,omitempty"`)
	assertConfigField(t, resultType, "ReasonCode", reflect.TypeOf(LiveE2EReasonCode("")), `json:"reasonCode,omitempty"`)
	assertConfigField(t, resultType, "Readiness", reflect.TypeOf((*LiveE2EReadinessMetadata)(nil)), `json:"readiness,omitempty"`)
	assertConfigField(t, resultType, "TemplateTrust", reflect.TypeOf((*LiveE2ETemplateTrustMetadata)(nil)), `json:"templateTrust,omitempty"`)
	assertConfigField(t, resultType, "Diagnostics", reflect.TypeOf([]LiveE2EPrerequisiteDiagnostic{}), `json:"diagnostics,omitempty"`)
}

func TestLiveE2ETemplateTrustProjectionRequiresMarkerAndTrustedLock(t *testing.T) {
	missingMarker := ProjectLiveE2ETemplateTrustMetadata(LiveE2ETemplateTrustProjectionInput{
		LiveMarker:    false,
		TemplateID:    "microvm-template-us008",
		TrustPolicyID: "strict-template-policy-us008",
		TemplateLock:  liveE2ETrustedTemplateLockFixture(),
	})
	assertTemplateTrustProjectionSkip(t, missingMarker, LiveE2EPrerequisiteTemplateTrustMarker, LiveE2EReasonTemplateTrustMarkerMissing)
	assertTemplateTrustProjectionNoUnsafeFragments(t, "missing marker", missingMarker, liveE2ETemplateTrustUnsafeFragments()...)

	missingLock := ProjectLiveE2ETemplateTrustMetadata(LiveE2ETemplateTrustProjectionInput{
		LiveMarker:    true,
		TemplateID:    "microvm-template-us008",
		TrustPolicyID: "strict-template-policy-us008",
	})
	assertTemplateTrustProjectionSkip(t, missingLock, LiveE2EPrerequisiteTemplateTrustMetadata, LiveE2EReasonTemplateTrustUnavailable)
	assertTemplateTrustProjectionNoUnsafeFragments(t, "missing lock", missingLock, liveE2ETemplateTrustUnsafeFragments()...)

	ready := ProjectLiveE2ETemplateTrustMetadata(LiveE2ETemplateTrustProjectionInput{
		LiveMarker:    true,
		TemplateID:    "MicroVM-Template-US008",
		TrustPolicyID: "Strict-Template-Policy-US008",
		TemplateLock:  liveE2ETrustedTemplateLockFixture(),
	})
	if !ready.CanRunLiveAction() {
		t.Fatalf("trusted template lock projection = %#v, want ready", ready)
	}
	if ready.TemplateTrust == nil {
		t.Fatal("templateTrust = nil")
	}
	if got := ready.TemplateTrust.TemplateID; got != "microvm-template-us008" {
		t.Fatalf("template ID = %q, want sanitized safe ID", got)
	}
	if got := ready.TemplateTrust.TrustPolicyID; got != "strict-template-policy-us008" {
		t.Fatalf("trust policy ID = %q, want sanitized safe ID", got)
	}
	if got, want := ready.TemplateTrust.ProvenanceLabels, []string{"document", "template_reference", "runtime_image", "source_artifact"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("provenance labels = %#v, want %#v", got, want)
	}
	if got := ready.TemplateTrust.Status; got != "trusted" {
		t.Fatalf("trust status = %q, want trusted", got)
	}
	if got, want := ready.TemplateTrust.ReasonCodes, []string{"document_digest", "template_reference_digest", "runtime_image_digest", "source_artifact_digest"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("reason codes = %#v, want %#v", got, want)
	}
	assertTemplateTrustProjectionNoUnsafeFragments(t, "ready projection", ready, liveE2ETemplateTrustUnsafeFragments()...)
}

func TestLiveE2ETemplateTrustProjectionSanitizesUnsafeAndRejectedMetadata(t *testing.T) {
	rejected := ProjectLiveE2ETemplateTrustMetadata(LiveE2ETemplateTrustProjectionInput{
		LiveMarker:    true,
		TemplateID:    "microvm-template-us008",
		TrustPolicyID: "strict-template-policy-us008",
		TemplateLock:  liveE2ERejectedTemplateLockFixture(),
	})
	if !rejected.ShouldSkipLiveAction() {
		t.Fatalf("rejected trust policy allowed live action: %#v", rejected)
	}
	if rejected.TemplateTrust == nil {
		t.Fatal("rejected projection templateTrust = nil, want sanitized diagnostic metadata")
	}
	if got := rejected.TemplateTrust.Status; got != "rejected" {
		t.Fatalf("rejected trust status = %q, want rejected", got)
	}
	if got, want := rejected.TemplateTrust.ReasonCodes, []string{"mutable_reference", "missing_digest_pin", "document_digest", "template_reference_digest", "runtime_image_digest", "source_artifact_digest"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("rejected reason codes = %#v, want %#v", got, want)
	}
	assertTemplateTrustProjectionNoUnsafeFragments(t, "rejected projection", rejected, liveE2ETemplateTrustUnsafeFragments()...)

	unsafeDirect := ProjectLiveE2ETemplateTrustMetadata(LiveE2ETemplateTrustProjectionInput{
		LiveMarker: true,
		TemplateTrust: LiveE2ETemplateTrustMetadata{
			TemplateID:       "https://registry.example.test/private?token=ghp_us008_secret",
			ProvenanceLabels: []string{"document", "ghcr.io/acme/private-template:latest?token=ghp_us008_secret"},
			TrustPolicyID:    "/Users/alice/.cache/hal/template-policy.json",
			Status:           "TRUSTED",
			ReasonCodes:      []string{"missing_digest_pin", "token=ghp_us008_secret", "/Users/alice/private-template.yaml"},
		},
	})
	if !unsafeDirect.ShouldSkipLiveAction() {
		t.Fatalf("unsafe direct template trust metadata allowed live action: %#v", unsafeDirect)
	}
	assertTemplateTrustProjectionSkip(t, unsafeDirect, LiveE2EPrerequisiteTemplateTrustMetadata, LiveE2EReasonTemplateTrustUnavailable)
	assertTemplateTrustProjectionNoUnsafeFragments(t, "unsafe direct projection", unsafeDirect, liveE2ETemplateTrustUnsafeFragments()...)
}

func liveE2ETrustedTemplateLockFixture() *sandboxruntime.RuntimeTemplateLockMetadata {
	return &sandboxruntime.RuntimeTemplateLockMetadata{
		Document: &sandboxruntime.RuntimeTemplateLockEntryMetadata{
			SourceKind:      "oci_artifact",
			ReferenceKind:   "oci_artifact",
			Status:          "locked",
			DigestAlgorithm: "sha256",
			DigestValue:     strings.Repeat("a", 64),
			ReasonCode:      "document_digest",
		},
		TemplateReference: &sandboxruntime.RuntimeTemplateLockEntryMetadata{
			SourceKind:      "template_reference",
			ReferenceKind:   "oci_artifact",
			Status:          "locked",
			DigestAlgorithm: "sha256",
			DigestValue:     strings.Repeat("b", 64),
			ReasonCode:      "template_reference_digest",
		},
		RuntimeImage: &sandboxruntime.RuntimeTemplateLockEntryMetadata{
			SourceKind:      "runtime_image",
			ReferenceKind:   "oci_image",
			Status:          "locked",
			DigestAlgorithm: "sha256",
			DigestValue:     strings.Repeat("c", 64),
			ReasonCode:      "runtime_image_digest",
		},
		SourceArtifact: &sandboxruntime.RuntimeTemplateLockEntryMetadata{
			SourceKind:      "source_artifact",
			ReferenceKind:   "git",
			Status:          "locked",
			DigestAlgorithm: "sha256",
			DigestValue:     strings.Repeat("d", 64),
			ReasonCode:      "source_artifact_digest",
		},
		TrustPolicy: &sandboxruntime.RuntimeTemplateTrustPolicyMetadata{
			Mode:            "strict",
			Decision:        "trusted",
			SourceKind:      "oci_artifact",
			ReferenceKind:   "oci_artifact",
			Status:          "locked",
			DigestAlgorithm: "sha256",
			DigestValue:     strings.Repeat("a", 64),
		},
	}
}

func liveE2ERejectedTemplateLockFixture() *sandboxruntime.RuntimeTemplateLockMetadata {
	lock := liveE2ETrustedTemplateLockFixture()
	lock.TrustPolicy.Decision = "rejected"
	lock.TrustPolicy.ReasonCodes = []string{"mutable_reference", "https://registry.example.test/private?token=ghp_us008_secret"}
	lock.TrustPolicy.ErrorCodes = []string{"missing_digest_pin", "/Users/alice/.cache/hal/template.yaml"}
	lock.TrustPolicy.WarningCodes = []string{"resolver_unavailable?token=ghp_us008_secret"}
	return lock
}

func assertTemplateTrustProjectionSkip(t *testing.T, result LiveE2ETemplateTrustProjectionResult, prerequisite LiveE2EPrerequisiteName, reason LiveE2EReasonCode) {
	t.Helper()
	if !result.ShouldSkipLiveAction() {
		t.Fatalf("ShouldSkipLiveAction() = false, want true for %#v", result)
	}
	if result.Status != LiveE2EReadinessSkipped {
		t.Fatalf("status = %q, want %q", result.Status, LiveE2EReadinessSkipped)
	}
	diagnostic := requireLiveE2EPreflightDiagnostic(t, result.Diagnostics, prerequisite)
	if diagnostic.ReasonCode != reason {
		t.Fatalf("%s reason = %q, want %q", prerequisite, diagnostic.ReasonCode, reason)
	}
	if result.TemplateTrust != nil {
		t.Fatalf("templateTrust = %#v, want omitted for missing marker diagnostic", result.TemplateTrust)
	}
}

func assertTemplateTrustProjectionNoUnsafeFragments(t *testing.T, label string, value any, forbidden ...string) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(%s) error: %v", label, err)
	}
	publicText := string(encoded)
	if result, ok := value.(LiveE2ETemplateTrustProjectionResult); ok {
		publicText += " " + LiveE2ETemplateTrustProjectionSkipMessage(result)
	}
	for _, unsafe := range forbidden {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("%s leaked unsafe template trust fragment %q in %s", label, unsafe, publicText)
		}
	}
}

func liveE2ETemplateTrustUnsafeFragments() []string {
	return []string{
		"registry.example.test",
		"ghcr.io",
		"token=",
		"ghp_us008_secret",
		"/Users/",
		"/tmp/",
		".sock",
		"provider_handle",
		"provider=",
		"cache/hal",
		"private-template",
	}
}
