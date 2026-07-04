package sandbox

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestUS004SandboxRuntimeStateTemplateLockDurableRoundTrip(t *testing.T) {
	payload := []byte(`{
		"driver": "rootless_podman",
		"isolationLevel": "container",
		"runtimeId": "runtime-us004",
		"image": "ghcr.io/acme/agent:latest",
		"workerId": "worker-us004",
		"templateLock": {
			"document": {
				"sourceKind": "local_file",
				"referenceKind": "local",
				"status": "locked",
				"digestAlgorithm": "sha256",
				"digestValue": "` + strings.Repeat("a", 64) + `",
				"sizeBytes": 2048,
				"lockedAt": "2026-07-04T06:18:17Z",
				"warningCodes": ["document_digest", "https://registry.example.test/private?token=ghp_us004_secret"],
				"reasonCode": "document_digest",
				"rawPath": "/Users/v/private/template.yaml"
			},
			"sourceArtifact": {
				"sourceKind": "source_artifact",
				"referenceKind": "oci_artifact",
				"status": "unresolved",
				"reasonCode": "resolver_unavailable",
				"digestAlgorithm": "sha256",
				"digestValue": "https://registry.example.test/private?token=ghp_us004_secret"
			},
			"trustPolicy": {
				"mode": "strict",
				"decision": "rejected",
				"sourceKind": "local_file",
				"referenceKind": "local",
				"status": "locked",
				"digestAlgorithm": "sha256",
				"digestValue": "` + strings.Repeat("b", 64) + `",
				"warningCodes": ["lock_provenance_mismatch", "token=ghp_us004_secret"],
				"errorCodes": ["unresolved_lock_entry", "/Users/v/private/template.yaml"],
				"reasonCodes": ["resolver_unavailable", "https://registry.example.test/private"],
				"rawReference": "https://user:secret@registry.example.test/private?token=ghp_us004_secret"
			}
		}
	}`)

	var state SandboxRuntimeState
	if err := json.Unmarshal(payload, &state); err != nil {
		t.Fatalf("Unmarshal(SandboxRuntimeState) error = %v", err)
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("Marshal(SandboxRuntimeState) error = %v", err)
	}
	assertUS004SandboxTemplateLockNoUnsafeFragments(t, string(encoded))

	var roundTrip SandboxRuntimeState
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatalf("round-trip Unmarshal(SandboxRuntimeState) error = %v", err)
	}
	lock := roundTrip.TemplateLock
	if lock == nil || lock.Document == nil || lock.TrustPolicy == nil {
		t.Fatalf("round-trip template lock = %#v, want document and trust policy metadata", lock)
	}
	if got := lock.Document.DigestValue; got != strings.Repeat("a", 64) {
		t.Fatalf("document digest = %q, want locked sha256 digest", got)
	}
	if got := lock.Document.LockedAt; got != "2026-07-04T06:18:17Z" {
		t.Fatalf("document lockedAt = %q, want stable UTC timestamp", got)
	}
	if got := lock.SourceArtifact.Status; got != SandboxTemplateLockStatusUnresolved {
		t.Fatalf("source artifact status = %q, want unresolved", got)
	}
	if lock.SourceArtifact.DigestValue != "" {
		t.Fatalf("unresolved source artifact digest = %q, want omitted", lock.SourceArtifact.DigestValue)
	}
	if got := lock.TrustPolicy.Decision; got != SandboxTemplateTrustPolicyDecisionRejected {
		t.Fatalf("trust policy decision = %q, want rejected", got)
	}
	if got := lock.TrustPolicy.DigestValue; got != strings.Repeat("b", 64) {
		t.Fatalf("trust policy digest = %q, want locked sha256 digest", got)
	}
}

func TestUS004CloneSandboxRuntimeStateCopiesSanitizedTemplateLock(t *testing.T) {
	runtime := &SandboxRuntimeState{
		Driver:         SandboxRuntimeDriverRootlessPodman,
		IsolationLevel: SandboxIsolationLevelContainer,
		RuntimeID:      "runtime-us004",
		Image:          "ghcr.io/acme/agent:latest",
		WorkerID:       "worker-us004",
		TemplateLock:   us004SandboxTemplateLockFixture(),
	}

	clone := CloneSandboxRuntimeState(runtime)
	if clone == nil || clone.TemplateLock == nil || clone.TemplateLock.Document == nil {
		t.Fatalf("CloneSandboxRuntimeState() = %#v, want cloned template lock", clone)
	}
	if clone == runtime || clone.TemplateLock == runtime.TemplateLock || clone.TemplateLock.Document == runtime.TemplateLock.Document {
		t.Fatalf("CloneSandboxRuntimeState() reused template lock pointers")
	}
	runtime.TemplateLock.Document.DigestValue = strings.Repeat("f", 64)
	if got := clone.TemplateLock.Document.DigestValue; got != strings.Repeat("a", 64) {
		t.Fatalf("cloned document digest changed to %q after source mutation", got)
	}

	encoded, err := json.Marshal(clone)
	if err != nil {
		t.Fatalf("Marshal(clone) error = %v", err)
	}
	assertUS004SandboxTemplateLockNoUnsafeFragments(t, string(encoded))
}

func TestUS004SandboxRuntimeStateMissingTemplateLockCompatibility(t *testing.T) {
	var state SandboxRuntimeState
	if err := json.Unmarshal([]byte(`{
		"driver": "ssh_machine",
		"isolationLevel": "vm",
		"runtimeId": "runtime-legacy"
	}`), &state); err != nil {
		t.Fatalf("Unmarshal legacy SandboxRuntimeState error = %v", err)
	}
	if state.TemplateLock != nil {
		t.Fatalf("legacy runtime state TemplateLock = %#v, want nil", state.TemplateLock)
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatalf("Marshal legacy SandboxRuntimeState error = %v", err)
	}
	if strings.Contains(string(encoded), `"templateLock"`) {
		t.Fatalf("legacy runtime state encoded templateLock unexpectedly: %s", encoded)
	}
}

func us004SandboxTemplateLockFixture() *SandboxTemplateLockMetadata {
	return &SandboxTemplateLockMetadata{
		Document: &SandboxTemplateLockEntryMetadata{
			SourceKind:      SandboxTemplateLockSourceKindLocalFile,
			ReferenceKind:   SandboxTemplateLockReferenceKindLocal,
			Status:          SandboxTemplateLockStatusLocked,
			DigestAlgorithm: "sha256",
			DigestValue:     strings.Repeat("a", 64),
			SizeBytes:       2048,
			LockedAt:        "2026-07-04T06:18:17Z",
			WarningCodes:    []string{SandboxTemplateLockReasonDocumentDigest, "token=ghp_us004_secret"},
			ReasonCode:      SandboxTemplateLockReasonDocumentDigest,
		},
		SourceArtifact: &SandboxTemplateLockEntryMetadata{
			SourceKind:    SandboxTemplateLockSourceKindSourceArtifact,
			ReferenceKind: SandboxTemplateLockReferenceKindOCIArtifact,
			Status:        SandboxTemplateLockStatusUnresolved,
			ReasonCode:    SandboxTemplateLockReasonResolverUnavailable,
		},
		TrustPolicy: &SandboxTemplateTrustPolicyMetadata{
			Mode:            SandboxTemplateTrustPolicyModeStrict,
			Decision:        SandboxTemplateTrustPolicyDecisionRejected,
			SourceKind:      SandboxTemplateLockSourceKindLocalFile,
			ReferenceKind:   SandboxTemplateLockReferenceKindLocal,
			Status:          SandboxTemplateLockStatusLocked,
			DigestAlgorithm: "sha256",
			DigestValue:     strings.Repeat("b", 64),
			WarningCodes:    []string{SandboxTemplateTrustPolicyCodeLockProvenanceMismatch, "token=ghp_us004_secret"},
			ErrorCodes:      []string{SandboxTemplateTrustPolicyCodeUnresolvedLockEntry, "/Users/v/private/template.yaml"},
			ReasonCodes:     []string{SandboxTemplateLockReasonResolverUnavailable, "https://registry.example.test/private"},
		},
	}
}

func assertUS004SandboxTemplateLockNoUnsafeFragments(t *testing.T, payload string) {
	t.Helper()
	for _, fragment := range []string{
		"/Users/v/private",
		"registry.example.test",
		"token=",
		"ghp_us004_secret",
		"user:secret",
		"rawReference",
		"rawPath",
	} {
		if strings.Contains(payload, fragment) {
			t.Fatalf("template lock payload leaked unsafe fragment %q: %s", fragment, payload)
		}
	}
}
