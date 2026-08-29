//go:build l8_verified_policy_artifact && l8_verified_pinned_callsite_evidence

package syscallpolicy

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestL8D7GeneratedPinnedCallsiteEvidenceImportsCanonicalAuthority(t *testing.T) {
	artifact, err := EmbeddedVerifiedPolicyArtifact()
	if err != nil {
		t.Fatalf("EmbeddedVerifiedPolicyArtifact() error = %v", err)
	}
	expected, err := EmbeddedExpectedPinnedCallsiteEvidence()
	if err != nil {
		t.Fatalf("EmbeddedExpectedPinnedCallsiteEvidence() error = %v", err)
	}
	encoded := readGeneratedPinnedCallsiteEvidence(t)
	set, err := ImportPinnedCallsiteEvidence(encoded, artifact, expected)
	if err != nil {
		t.Fatalf("ImportPinnedCallsiteEvidence() error = %v", err)
	}
	bindings := set.BinaryBindings().Bindings()
	evidence := set.Evidence()
	if set.SHA256() != expected.SHA256() || set.ArtifactSHA256() != artifact.SHA256() || set.SourceLockSHA256() != artifact.SourceLockSHA256() {
		t.Fatal("generated HL8E did not correlate with the issued HL8Q artifact")
	}
	if len(bindings) != 1 || bindings[0].Role() != RoleLaunchBase || bindings[0].Kind() != BinaryBindingKindPinnedGoRuntime || len(evidence) != 1 {
		t.Fatal("generated HL8E does not bind the exact launch-base pinned Go runtime callsite")
	}
	if evidence[0].InstructionOffset()+2 > bindings[0].TextLength() || evidence[0].ObservedInstructionSHA256() == ([32]byte{}) {
		t.Fatal("generated HL8E instruction/offset/text-length checks are incomplete")
	}
}

func readGeneratedPinnedCallsiteEvidence(t *testing.T) []byte {
	t.Helper()
	_, sourcePath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate generated HL8E source")
	}
	path := filepath.Join(filepath.Dir(sourcePath), "..", "..", "..", "..", "..", "tools", "microvm", "l8", "policy", "verified-pinned-callsites.hl8e")
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open generated HL8E: %v", err)
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, MaxPinnedCallsiteEvidenceBytes+1))
	if err != nil || len(encoded) == 0 || len(encoded) > MaxPinnedCallsiteEvidenceBytes {
		t.Fatal("generated HL8E is unavailable or outside bounds")
	}
	return encoded
}
