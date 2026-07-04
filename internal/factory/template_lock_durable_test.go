package factory

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestUS004FactorySandboxMetadataSetTemplateLockFromRuntimeSanitizesSelectedTemplate(t *testing.T) {
	metadata := &SandboxMetadata{Name: "factory-us004", Provider: "local", Status: sandbox.StatusRunning}
	runtime := &sandbox.SandboxRuntimeState{TemplateLock: us004FactoryTemplateLockFixture()}

	metadata.SetTemplateLockFromRuntime(runtime)
	if metadata.TemplateLock == nil || metadata.TemplateLock.Document == nil || metadata.TemplateLock.TrustPolicy == nil {
		t.Fatalf("SetTemplateLockFromRuntime() TemplateLock = %#v, want sanitized lock", metadata.TemplateLock)
	}
	runtime.TemplateLock.Document.DigestValue = strings.Repeat("f", 64)
	if got := metadata.TemplateLock.Document.DigestValue; got != strings.Repeat("a", 64) {
		t.Fatalf("factory template lock changed to %q after source mutation", got)
	}

	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal(SandboxMetadata) error = %v", err)
	}
	assertUS004FactoryTemplateLockNoUnsafeFragments(t, string(encoded))

	var roundTrip SandboxMetadata
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatalf("round-trip Unmarshal(SandboxMetadata) error = %v", err)
	}
	if roundTrip.TemplateLock == nil || roundTrip.TemplateLock.TrustPolicy == nil {
		t.Fatalf("round-trip TemplateLock = %#v, want trust policy metadata", roundTrip.TemplateLock)
	}
	if got := roundTrip.TemplateLock.TrustPolicy.Decision; got != sandbox.SandboxTemplateTrustPolicyDecisionRejected {
		t.Fatalf("trust policy decision = %q, want rejected", got)
	}
}

func TestUS004FactoryRecordsWithoutTemplateLockSurfaceRemainUnchanged(t *testing.T) {
	for _, tt := range []struct {
		label string
		typ   reflect.Type
	}{
		{label: "RunRecord", typ: reflect.TypeOf(RunRecord{})},
		{label: "EventRecord", typ: reflect.TypeOf(EventRecord{})},
		{label: "SandboxRuntimeMetadata", typ: reflect.TypeOf(SandboxRuntimeMetadata{})},
	} {
		t.Run(tt.label, func(t *testing.T) {
			if _, ok := tt.typ.FieldByName("TemplateLock"); ok {
				t.Fatalf("%s unexpectedly gained TemplateLock; Phase 59 should use existing SandboxMetadata surface only", tt.label)
			}
		})
	}
}

func TestUS004FactorySandboxMetadataMissingTemplateLockCompatibility(t *testing.T) {
	var metadata SandboxMetadata
	if err := json.Unmarshal([]byte(`{"name":"factory-us004","provider":"local","status":"running"}`), &metadata); err != nil {
		t.Fatalf("Unmarshal legacy SandboxMetadata error = %v", err)
	}
	if metadata.TemplateLock != nil {
		t.Fatalf("legacy SandboxMetadata TemplateLock = %#v, want nil", metadata.TemplateLock)
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal legacy SandboxMetadata error = %v", err)
	}
	if strings.Contains(string(encoded), `"templateLock"`) {
		t.Fatalf("legacy SandboxMetadata encoded templateLock unexpectedly: %s", encoded)
	}
}

func us004FactoryTemplateLockFixture() *sandbox.SandboxTemplateLockMetadata {
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

func assertUS004FactoryTemplateLockNoUnsafeFragments(t *testing.T, payload string) {
	t.Helper()
	for _, fragment := range []string{
		"/Users/v/private",
		"registry.example.test",
		"token=",
		"ghp_us004_secret",
	} {
		if strings.Contains(payload, fragment) {
			t.Fatalf("factory template lock payload leaked unsafe fragment %q: %s", fragment, payload)
		}
	}
}
