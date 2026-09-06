//go:build !l8_verified_policy_artifact

package syscallpolicy

import "testing"

func TestL8SyscallPolicyDefaultArtifactIsUnavailable(t *testing.T) {
	t.Parallel()

	artifact, err := EmbeddedVerifiedPolicyArtifact()
	if artifact.SHA256() != ([32]byte{}) || contractErrorCode(err) != ErrorCodeMissingSection {
		t.Fatalf("EmbeddedVerifiedPolicyArtifact() = (%x, %v), want zero/missing-section", artifact.SHA256(), err)
	}
}
