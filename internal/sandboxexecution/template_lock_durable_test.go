package sandboxexecution

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestUS004ManifestRuntimeTemplateLockBackfillsDurableTopLevelLock(t *testing.T) {
	manifest := Manifest{
		ID:        "run-us004-template-lock",
		Purpose:   PurposeRun,
		Status:    StatusRunning,
		StartedAt: time.Date(2026, 7, 4, 6, 18, 17, 0, time.UTC),
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:       sandbox.SandboxRuntimeDriverRootlessPodman,
			RuntimeID:    "runtime-us004",
			TemplateLock: us004ExecutionTemplateLockFixture(),
		},
	}

	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal(Manifest) error = %v", err)
	}
	assertUS004ExecutionTemplateLockNoUnsafeFragments(t, string(encoded))

	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatalf("Unmarshal encoded manifest object error = %v", err)
	}
	if _, ok := object["templateLock"]; !ok {
		t.Fatalf("manifest JSON omitted top-level templateLock from runtime lock: %s", encoded)
	}

	var roundTrip Manifest
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatalf("round-trip Unmarshal(Manifest) error = %v", err)
	}
	if roundTrip.TemplateLock == nil || roundTrip.TemplateLock.TrustPolicy == nil {
		t.Fatalf("round-trip manifest TemplateLock = %#v, want trust policy metadata", roundTrip.TemplateLock)
	}
	if got := roundTrip.TemplateLock.TrustPolicy.Decision; got != sandbox.SandboxTemplateTrustPolicyDecisionRejected {
		t.Fatalf("trust policy decision = %q, want rejected", got)
	}
	if got := roundTrip.TemplateLock.Document.DigestValue; got != strings.Repeat("a", 64) {
		t.Fatalf("document digest = %q, want locked sha256 digest", got)
	}
}

func TestUS004ManifestSetTemplateLockFromRuntimeSanitizesSelectedTemplate(t *testing.T) {
	manifest := &Manifest{ID: "run-us004-template-lock", Purpose: PurposeRun, Status: StatusRunning}
	runtime := &sandbox.SandboxRuntimeState{TemplateLock: us004ExecutionTemplateLockFixture()}

	manifest.SetTemplateLockFromRuntime(runtime)
	if manifest.TemplateLock == nil || manifest.TemplateLock.Document == nil || manifest.TemplateLock.TrustPolicy == nil {
		t.Fatalf("SetTemplateLockFromRuntime() TemplateLock = %#v, want sanitized lock", manifest.TemplateLock)
	}
	runtime.TemplateLock.Document.DigestValue = strings.Repeat("f", 64)
	if got := manifest.TemplateLock.Document.DigestValue; got != strings.Repeat("a", 64) {
		t.Fatalf("manifest template lock changed to %q after source mutation", got)
	}
}

func TestUS004ManifestMissingTemplateLockCompatibility(t *testing.T) {
	var manifest Manifest
	if err := json.Unmarshal([]byte(`{
		"id": "run-us004-legacy",
		"purpose": "run",
		"status": "succeeded",
		"startedAt": "2026-07-04T06:18:17Z"
	}`), &manifest); err != nil {
		t.Fatalf("Unmarshal legacy manifest error = %v", err)
	}
	if manifest.TemplateLock != nil {
		t.Fatalf("legacy manifest TemplateLock = %#v, want nil", manifest.TemplateLock)
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal legacy manifest error = %v", err)
	}
	if strings.Contains(string(encoded), `"templateLock"`) {
		t.Fatalf("legacy manifest encoded templateLock unexpectedly: %s", encoded)
	}
}

func us004ExecutionTemplateLockFixture() *sandbox.SandboxTemplateLockMetadata {
	return &sandbox.SandboxTemplateLockMetadata{
		Document: &sandbox.SandboxTemplateLockEntryMetadata{
			SourceKind:      sandbox.SandboxTemplateLockSourceKindLocalFile,
			ReferenceKind:   sandbox.SandboxTemplateLockReferenceKindLocal,
			Status:          sandbox.SandboxTemplateLockStatusLocked,
			DigestAlgorithm: "sha256",
			DigestValue:     strings.Repeat("a", 64),
			SizeBytes:       2048,
			LockedAt:        "2026-07-04T06:18:17Z",
			WarningCodes:    []string{sandbox.SandboxTemplateLockReasonDocumentDigest, "token=ghp_us004_secret"},
			ReasonCode:      sandbox.SandboxTemplateLockReasonDocumentDigest,
		},
		SourceArtifact: &sandbox.SandboxTemplateLockEntryMetadata{
			SourceKind:    sandbox.SandboxTemplateLockSourceKindSourceArtifact,
			ReferenceKind: sandbox.SandboxTemplateLockReferenceKindOCIArtifact,
			Status:        sandbox.SandboxTemplateLockStatusUnresolved,
			ReasonCode:    sandbox.SandboxTemplateLockReasonResolverUnavailable,
		},
		TrustPolicy: &sandbox.SandboxTemplateTrustPolicyMetadata{
			Mode:            sandbox.SandboxTemplateTrustPolicyModeStrict,
			Decision:        sandbox.SandboxTemplateTrustPolicyDecisionRejected,
			SourceKind:      sandbox.SandboxTemplateLockSourceKindLocalFile,
			ReferenceKind:   sandbox.SandboxTemplateLockReferenceKindLocal,
			Status:          sandbox.SandboxTemplateLockStatusLocked,
			DigestAlgorithm: "sha256",
			DigestValue:     strings.Repeat("b", 64),
			WarningCodes:    []string{sandbox.SandboxTemplateTrustPolicyCodeLockProvenanceMismatch, "token=ghp_us004_secret"},
			ErrorCodes:      []string{sandbox.SandboxTemplateTrustPolicyCodeUnresolvedLockEntry, "/Users/v/private/template.yaml"},
			ReasonCodes:     []string{sandbox.SandboxTemplateLockReasonResolverUnavailable, "https://registry.example.test/private"},
		},
	}
}

func assertUS004ExecutionTemplateLockNoUnsafeFragments(t *testing.T, payload string) {
	t.Helper()
	for _, fragment := range []string{
		"/Users/v/private",
		"registry.example.test",
		"token=",
		"ghp_us004_secret",
	} {
		if strings.Contains(payload, fragment) {
			t.Fatalf("manifest template lock payload leaked unsafe fragment %q: %s", fragment, payload)
		}
	}
}
