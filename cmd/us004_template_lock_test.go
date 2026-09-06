package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestUS004FactorySandboxMetadataFromStatePersistsRuntimeTemplateLock(t *testing.T) {
	_, metadata := factorySandboxMetadataFromState(&sandbox.SandboxState{
		Name:     "factory-us004",
		Provider: "local",
		Status:   sandbox.StatusRunning,
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:       sandbox.SandboxRuntimeDriverRootlessPodman,
			RuntimeID:    "runtime-us004",
			TemplateLock: us004CommandTemplateLockFixture(),
		},
	})
	if metadata == nil {
		t.Fatal("factorySandboxMetadataFromState() metadata = nil")
	}
	if metadata.TemplateLock == nil || metadata.TemplateLock.TrustPolicy == nil {
		t.Fatalf("factorySandboxMetadataFromState() TemplateLock = %#v, want selected template trust metadata", metadata.TemplateLock)
	}
	if got := metadata.TemplateLock.Document.DigestValue; got != strings.Repeat("a", 64) {
		t.Fatalf("document digest = %q, want locked sha256 digest", got)
	}
	if got := metadata.TemplateLock.SourceArtifact.Status; got != sandbox.SandboxTemplateLockStatusUnresolved {
		t.Fatalf("source artifact status = %q, want unresolved", got)
	}
	if got := metadata.TemplateLock.TrustPolicy.Decision; got != sandbox.SandboxTemplateTrustPolicyDecisionRejected {
		t.Fatalf("trust policy decision = %q, want rejected", got)
	}

	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal(factory sandbox metadata) error = %v", err)
	}
	for _, fragment := range []string{"/Users/v/private", "registry.example.test", "token=", "ghp_us004_secret"} {
		if strings.Contains(string(encoded), fragment) {
			t.Fatalf("factory sandbox metadata leaked unsafe fragment %q: %s", fragment, encoded)
		}
	}
}

func us004CommandTemplateLockFixture() *sandbox.SandboxTemplateLockMetadata {
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
