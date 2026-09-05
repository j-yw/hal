package sandboxruntime

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestUS005RuntimeTemplateStatusProjectionStates(t *testing.T) {
	tests := []struct {
		name           string
		lock           *RuntimeTemplateLockMetadata
		wantPresent    bool
		wantLockStatus string
		wantDecision   string
		wantReasons    []string
	}{
		{
			name:           "locked trusted",
			lock:           us005RuntimeTemplateLockTrusted(),
			wantPresent:    true,
			wantLockStatus: "locked",
			wantDecision:   "trusted",
			wantReasons: []string{
				"document_digest",
				"template_reference_digest",
				"runtime_image_digest",
				"source_artifact_digest",
			},
		},
		{
			name:           "unresolved unavailable",
			lock:           us005RuntimeTemplateLockUnresolved(),
			wantPresent:    true,
			wantLockStatus: "unresolved",
			wantDecision:   "unavailable",
			wantReasons: []string{
				"unresolved_mutable_reference",
				"unresolved_lock_entry",
			},
		},
		{
			name:           "rejected locked",
			lock:           us005RuntimeTemplateLockRejected(),
			wantPresent:    true,
			wantLockStatus: "locked",
			wantDecision:   "rejected",
			wantReasons: []string{
				"mutable_reference",
				"missing_digest_pin",
				"lock_provenance_mismatch",
			},
		},
		{
			name:        "absent",
			lock:        nil,
			wantPresent: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := ProjectRuntimeTemplateStatusMetadata(tt.lock)
			if !tt.wantPresent {
				if status != nil {
					t.Fatalf("ProjectRuntimeTemplateStatusMetadata() = %#v, want nil", status)
				}
				return
			}
			if status == nil {
				t.Fatal("ProjectRuntimeTemplateStatusMetadata() = nil, want projected status")
			}
			if status.LockStatus != tt.wantLockStatus {
				t.Fatalf("lockStatus = %q, want %q", status.LockStatus, tt.wantLockStatus)
			}
			if status.TrustDecision != tt.wantDecision {
				t.Fatalf("trustDecision = %q, want %q", status.TrustDecision, tt.wantDecision)
			}
			if got, want := status.ProvenanceLabels, []string{"document", "template_reference", "runtime_image", "source_artifact"}; !reflect.DeepEqual(got, want) {
				t.Fatalf("provenanceLabels = %#v, want %#v", got, want)
			}
			for _, want := range tt.wantReasons {
				if !containsRuntimeTemplateStatusReason(status.ReasonCodes, want) {
					t.Fatalf("reasonCodes = %#v, want %q", status.ReasonCodes, want)
				}
			}
		})
	}
}

func TestUS005RuntimeMetadataProjectsTemplateStatusAndRedactsUnsafeInput(t *testing.T) {
	metadata := RuntimeMetadata{
		Backend:      "microvm",
		TemplateLock: us005RuntimeTemplateLockRejected(),
		TemplateStatus: &RuntimeTemplateStatusMetadata{
			LockStatus:       "LOCKED",
			TrustMode:        "STRICT",
			TrustDecision:    "TRUSTED",
			ProvenanceLabels: []string{"document", "https://registry.example.test/private?token=ghp_us005_secret"},
			ReasonCodes:      []string{"missing_digest_pin", "/Users/alice/.cache/hal/template.yaml"},
		},
	}

	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal(RuntimeMetadata) error = %v", err)
	}
	publicText := string(encoded)
	for _, want := range []string{
		`"templateLock":`,
		`"templateStatus":`,
		`"lockStatus":"locked"`,
		`"trustMode":"strict"`,
		`"trustDecision":"rejected"`,
		`"provenanceLabels":["document","template_reference","runtime_image","source_artifact"]`,
		`"mutable_reference"`,
		`"missing_digest_pin"`,
		`"lock_provenance_mismatch"`,
	} {
		if !strings.Contains(publicText, want) {
			t.Fatalf("RuntimeMetadata JSON %s missing %s", publicText, want)
		}
	}
	assertUS005RuntimeTemplateProjectionNoUnsafeFragments(t, publicText)

	var decoded RuntimeMetadata
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal(RuntimeMetadata) error = %v", err)
	}
	if decoded.TemplateStatus == nil {
		t.Fatal("decoded TemplateStatus = nil")
	}
	if decoded.TemplateStatus.TrustDecision != "rejected" {
		t.Fatalf("decoded trustDecision = %q, want rejected", decoded.TemplateStatus.TrustDecision)
	}
}

func TestUS005RuntimeMetadataDerivesTemplateStatusWhenOnlyLockIsPresent(t *testing.T) {
	metadata := RuntimeMetadata{
		TemplateLock: us005RuntimeTemplateLockUnresolved(),
	}

	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal(RuntimeMetadata) error = %v", err)
	}
	publicText := string(encoded)
	for _, want := range []string{
		`"templateStatus":`,
		`"lockStatus":"unresolved"`,
		`"trustDecision":"unavailable"`,
		`"unresolved_mutable_reference"`,
	} {
		if !strings.Contains(publicText, want) {
			t.Fatalf("RuntimeMetadata JSON %s missing %s", publicText, want)
		}
	}

	var decoded RuntimeMetadata
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal(RuntimeMetadata) error = %v", err)
	}
	if decoded.TemplateStatus == nil || decoded.TemplateStatus.LockStatus != "unresolved" {
		t.Fatalf("decoded TemplateStatus = %#v, want unresolved status", decoded.TemplateStatus)
	}
}

func TestUS004RuntimeTemplateProjectionCarriesOnlySanitizedTrustAndDigestLabels(t *testing.T) {
	lock := us005RuntimeTemplateLockTrusted()
	lock.TemplateReference.WarningCodes = []string{
		"mutable_reference",
		"https://registry.example.test/template:latest?token=ghp_us004_secret",
	}
	lock.TrustPolicy.WarningCodes = []string{
		"missing_digest_pin",
		"/Users/alice/private-template.yaml",
	}
	lock.TrustPolicy.ReasonCodes = []string{
		"mutable_reference",
		"Authorization: Bearer ghp_us004_secret",
	}
	metadata := RuntimeMetadata{
		Backend:      "microvm",
		TemplateLock: lock,
		TemplateStatus: &RuntimeTemplateStatusMetadata{
			LockStatus:       "unresolved",
			TrustMode:        "advisory",
			TrustDecision:    "advisory",
			ProvenanceLabels: []string{"provider.internal", "document"},
			ReasonCodes:      []string{"https://registry.example.test/private?token=ghp_us004_secret"},
		},
	}

	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal(RuntimeMetadata) error = %v", err)
	}
	publicText := string(encoded)
	for _, want := range []string{
		`"templateLock":`,
		`"templateStatus":`,
		`"lockStatus":"locked"`,
		`"trustMode":"strict"`,
		`"trustDecision":"trusted"`,
		`"digestAlgorithm":"sha256"`,
		`"digestValue":"` + strings.Repeat("e", 64) + `"`,
		`"provenanceLabels":["document","template_reference","runtime_image","source_artifact"]`,
		`"mutable_reference"`,
		`"missing_digest_pin"`,
	} {
		if !strings.Contains(publicText, want) {
			t.Fatalf("RuntimeMetadata JSON %s missing %s", publicText, want)
		}
	}
	assertUS005RuntimeTemplateProjectionNoUnsafeFragments(t, publicText)
}

func us005RuntimeTemplateLockTrusted() *RuntimeTemplateLockMetadata {
	return &RuntimeTemplateLockMetadata{
		Document:          us005RuntimeTemplateLockEntry("local_file", "local", "document_digest", "a", "locked"),
		TemplateReference: us005RuntimeTemplateLockEntry("template_reference", "oci_artifact", "template_reference_digest", "b", "locked"),
		RuntimeImage:      us005RuntimeTemplateLockEntry("runtime_image", "oci_image", "runtime_image_digest", "c", "locked"),
		SourceArtifact:    us005RuntimeTemplateLockEntry("source_artifact", "git", "source_artifact_digest", "d", "locked"),
		TrustPolicy: &RuntimeTemplateTrustPolicyMetadata{
			Mode:            "strict",
			Decision:        "trusted",
			SourceKind:      "local_file",
			ReferenceKind:   "local",
			Status:          "locked",
			DigestAlgorithm: "sha256",
			DigestValue:     strings.Repeat("e", 64),
		},
	}
}

func us005RuntimeTemplateLockUnresolved() *RuntimeTemplateLockMetadata {
	lock := us005RuntimeTemplateLockTrusted()
	lock.RuntimeImage = &RuntimeTemplateLockEntryMetadata{
		SourceKind:    "runtime_image",
		ReferenceKind: "oci_image",
		Status:        "unresolved",
		ReasonCode:    "unresolved_mutable_reference",
		WarningCodes:  []string{"https://registry.example.test/image:latest?token=ghp_us005_secret"},
	}
	lock.TrustPolicy.Decision = "unavailable"
	lock.TrustPolicy.Status = "unresolved"
	lock.TrustPolicy.ReasonCodes = []string{"unresolved_lock_entry", "https://registry.example.test/private"}
	lock.TrustPolicy.ErrorCodes = []string{"unresolved_lock_entry", "/Users/alice/private-template.yaml"}
	return lock
}

func us005RuntimeTemplateLockRejected() *RuntimeTemplateLockMetadata {
	lock := us005RuntimeTemplateLockTrusted()
	lock.TrustPolicy.Decision = "rejected"
	lock.TrustPolicy.ReasonCodes = []string{"mutable_reference", "https://registry.example.test/private?token=ghp_us005_secret"}
	lock.TrustPolicy.ErrorCodes = []string{"missing_digest_pin", "/Users/alice/.cache/hal/template.yaml"}
	lock.TrustPolicy.WarningCodes = []string{"lock_provenance_mismatch", "unix:///tmp/hal-template.sock"}
	return lock
}

func us005RuntimeTemplateLockEntry(sourceKind, referenceKind, reasonCode, digestSeed, status string) *RuntimeTemplateLockEntryMetadata {
	return &RuntimeTemplateLockEntryMetadata{
		SourceKind:      sourceKind,
		ReferenceKind:   referenceKind,
		Status:          status,
		DigestAlgorithm: "sha256",
		DigestValue:     strings.Repeat(digestSeed, 64),
		SizeBytes:       4096,
		LockedAt:        "2026-07-04T06:18:17Z",
		WarningCodes:    []string{reasonCode, "token=ghp_us005_secret"},
		ReasonCode:      reasonCode,
	}
}

func containsRuntimeTemplateStatusReason(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func assertUS005RuntimeTemplateProjectionNoUnsafeFragments(t *testing.T, payload string) {
	t.Helper()
	for _, fragment := range []string{
		"registry.example.test",
		"token=",
		"ghp_us005_secret",
		"/Users/",
		"/tmp/",
		".sock",
		"unix://",
		"adapter",
	} {
		if strings.Contains(payload, fragment) {
			t.Fatalf("runtime template projection leaked unsafe fragment %q: %s", fragment, payload)
		}
	}
}
