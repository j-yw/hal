//go:build l8_verified_policy_artifact

package syscallpolicy

import (
	"crypto/sha256"
	"errors"
	"testing"
)

func TestL8D7GeneratedArtifactImportsCanonicalNonzeroAuthority(t *testing.T) {
	artifact, err := EmbeddedVerifiedPolicyArtifact()
	if err != nil {
		t.Fatalf("EmbeddedVerifiedPolicyArtifact() error code = %v", d7ContractErrorCode(err))
	}
	if artifact.SHA256() == ([sha256.Size]byte{}) || artifact.SourceLockSHA256() == ([sha256.Size]byte{}) {
		t.Fatal("generated D7 artifact returned zero authority")
	}
	if artifact.SHA256() != embeddedVerifiedPolicyArtifactSHA256 || artifact.SourceLockSHA256() != embeddedVerifiedPolicySourceLockSHA256 {
		t.Fatal("generated D7 artifact does not match its independently embedded expectations")
	}
	if len(embeddedVerifiedPolicyArtifactBytes) == 0 || len(embeddedVerifiedPolicyArtifactBytes) > MaxVerifiedPolicyArtifactBytes {
		t.Fatalf("generated D7 artifact byte length = %d", len(embeddedVerifiedPolicyArtifactBytes))
	}
	if len(artifact.Catalog()) < 300 || len(artifact.Rules()) != 44 || len(artifact.Transitions()) != 9 {
		t.Fatalf("generated D7 topology = catalog:%d rules:%d transitions:%d", len(artifact.Catalog()), len(artifact.Rules()), len(artifact.Transitions()))
	}
	if len(artifact.Workload().Rules()) != 1 || len(artifact.Runtime().Rules()) != 19 || artifact.Runtime().GoVersion() != "go1.25.7" {
		t.Fatal("generated D7 workload/runtime projections are incomplete")
	}
	legacyFound := false
	for _, entry := range artifact.Catalog() {
		if entry.Number() == 156 {
			legacyFound = entry.Name() == "_sysctl"
		}
	}
	if !legacyFound {
		t.Fatal("generated D7 catalog does not preserve exact legacy row 156,_sysctl")
	}
}

func TestL8D7GeneratedArtifactInputMutationFailsClosed(t *testing.T) {
	mutated := append([]byte(nil), embeddedVerifiedPolicyArtifactBytes...)
	mutated[len(mutated)-1] ^= 0x01
	artifact, err := ImportVerifiedPolicyArtifact(mutated, ExpectedPolicyArtifact{
		sha256: embeddedVerifiedPolicyArtifactSHA256,
		issuer: expectedIssuer{issued: true},
	})
	if artifact.artifact != nil || artifact.SHA256() != ([sha256.Size]byte{}) {
		t.Fatal("mutated generated artifact returned authority")
	}
	if got := d7ContractErrorCode(err); got != ErrorCodeDigestMismatch {
		t.Fatalf("mutated generated artifact error = %v, want digest-mismatch", got)
	}
}

func d7ContractErrorCode(err error) ErrorCode {
	var contractError *ContractError
	if !errors.As(err, &contractError) {
		return 0
	}
	return contractError.Code()
}
