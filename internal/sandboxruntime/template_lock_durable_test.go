package sandboxruntime

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestUS004RuntimeMetadataTemplateLockDurableRoundTrip(t *testing.T) {
	payload := []byte(`{
		"backend": "microvm",
		"templateLock": {
			"document": {
				"sourceKind": "oci_artifact",
				"referenceKind": "oci_artifact",
				"status": "locked",
				"digestAlgorithm": "sha256",
				"digestValue": "` + strings.Repeat("c", 64) + `",
				"sizeBytes": 4096,
				"lockedAt": "2026-07-04T06:18:17Z",
				"reasonCode": "document_digest",
				"localPath": "/Users/v/private/template.yaml"
			},
			"runtimeImage": {
				"sourceKind": "runtime_image",
				"referenceKind": "oci_image",
				"status": "unresolved",
				"reasonCode": "mutable_reference",
				"digestValue": "https://registry.example.test/image:latest?token=ghp_us004_secret"
			},
			"trustPolicy": {
				"mode": "strict",
				"decision": "rejected",
				"sourceKind": "oci_artifact",
				"referenceKind": "oci_artifact",
				"status": "locked",
				"digestAlgorithm": "sha256",
				"digestValue": "` + strings.Repeat("d", 64) + `",
				"warningCodes": ["resolver_unavailable", "token=ghp_us004_secret"],
				"errorCodes": ["lock_provenance_mismatch", "/Users/v/private/template.yaml"],
				"reasonCodes": ["mutable_reference", "https://registry.example.test/private"]
			}
		}
	}`)

	var metadata RuntimeMetadata
	if err := json.Unmarshal(payload, &metadata); err != nil {
		t.Fatalf("Unmarshal(RuntimeMetadata) error = %v", err)
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal(RuntimeMetadata) error = %v", err)
	}
	assertUS004RuntimeTemplateLockNoUnsafeFragments(t, string(encoded))

	var roundTrip RuntimeMetadata
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatalf("round-trip Unmarshal(RuntimeMetadata) error = %v", err)
	}
	lock := roundTrip.TemplateLock
	if lock == nil || lock.Document == nil || lock.RuntimeImage == nil || lock.TrustPolicy == nil {
		t.Fatalf("round-trip runtime template lock = %#v, want document, runtime image, and trust policy", lock)
	}
	if got := lock.Document.DigestValue; got != strings.Repeat("c", 64) {
		t.Fatalf("document digest = %q, want locked sha256 digest", got)
	}
	if got := lock.RuntimeImage.Status; got != runtimeTemplateLockStatusUnresolved {
		t.Fatalf("runtime image status = %q, want unresolved", got)
	}
	if lock.RuntimeImage.DigestValue != "" {
		t.Fatalf("unresolved runtime image digest = %q, want omitted", lock.RuntimeImage.DigestValue)
	}
	if got := lock.TrustPolicy.Decision; got != runtimeTemplateTrustPolicyDecisionRejected {
		t.Fatalf("trust policy decision = %q, want rejected", got)
	}
	if got := lock.TrustPolicy.DigestValue; got != strings.Repeat("d", 64) {
		t.Fatalf("trust policy digest = %q, want locked sha256 digest", got)
	}
}

func TestUS004CloneRuntimeTemplateLockMetadataCopiesSanitizedLock(t *testing.T) {
	source := &RuntimeTemplateLockMetadata{
		Document: &RuntimeTemplateLockEntryMetadata{
			SourceKind:      runtimeTemplateLockSourceKindOCIArtifact,
			ReferenceKind:   runtimeTemplateLockReferenceKindOCIArtifact,
			Status:          runtimeTemplateLockStatusLocked,
			DigestAlgorithm: "sha256",
			DigestValue:     strings.Repeat("c", 64),
			SizeBytes:       4096,
			LockedAt:        "2026-07-04T06:18:17Z",
			WarningCodes:    []string{"document_digest", "token=ghp_us004_secret"},
			ReasonCode:      "document_digest",
		},
		TrustPolicy: &RuntimeTemplateTrustPolicyMetadata{
			Mode:            runtimeTemplateTrustPolicyModeStrict,
			Decision:        runtimeTemplateTrustPolicyDecisionRejected,
			SourceKind:      runtimeTemplateLockSourceKindOCIArtifact,
			ReferenceKind:   runtimeTemplateLockReferenceKindOCIArtifact,
			Status:          runtimeTemplateLockStatusLocked,
			DigestAlgorithm: "sha256",
			DigestValue:     strings.Repeat("d", 64),
			WarningCodes:    []string{runtimeTemplateTrustPolicyCodeResolverUnavailable, "token=ghp_us004_secret"},
			ErrorCodes:      []string{runtimeTemplateTrustPolicyCodeLockProvenanceMismatch, "/Users/v/private/template.yaml"},
			ReasonCodes:     []string{"mutable_reference", "https://registry.example.test/private"},
		},
	}

	clone := CloneRuntimeTemplateLockMetadata(source)
	if clone == nil || clone.Document == nil || clone.TrustPolicy == nil {
		t.Fatalf("CloneRuntimeTemplateLockMetadata() = %#v, want cloned lock metadata", clone)
	}
	if clone == source || clone.Document == source.Document || clone.TrustPolicy == source.TrustPolicy {
		t.Fatalf("CloneRuntimeTemplateLockMetadata() reused source pointers")
	}
	source.Document.DigestValue = strings.Repeat("e", 64)
	if got := clone.Document.DigestValue; got != strings.Repeat("c", 64) {
		t.Fatalf("cloned document digest changed to %q after source mutation", got)
	}
}

func TestUS004RuntimeMetadataMissingTemplateLockCompatibility(t *testing.T) {
	var metadata RuntimeMetadata
	if err := json.Unmarshal([]byte(`{"backend":"rootless_podman"}`), &metadata); err != nil {
		t.Fatalf("Unmarshal legacy RuntimeMetadata error = %v", err)
	}
	if metadata.TemplateLock != nil {
		t.Fatalf("legacy RuntimeMetadata TemplateLock = %#v, want nil", metadata.TemplateLock)
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal legacy RuntimeMetadata error = %v", err)
	}
	if strings.Contains(string(encoded), `"templateLock"`) {
		t.Fatalf("legacy RuntimeMetadata encoded templateLock unexpectedly: %s", encoded)
	}
}

func assertUS004RuntimeTemplateLockNoUnsafeFragments(t *testing.T, payload string) {
	t.Helper()
	for _, fragment := range []string{
		"/Users/v/private",
		"registry.example.test",
		"token=",
		"ghp_us004_secret",
		"localPath",
	} {
		if strings.Contains(payload, fragment) {
			t.Fatalf("runtime template lock payload leaked unsafe fragment %q: %s", fragment, payload)
		}
	}
}
