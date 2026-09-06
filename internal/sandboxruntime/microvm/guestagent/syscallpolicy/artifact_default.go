//go:build !l8_verified_policy_artifact

package syscallpolicy

// EmbeddedVerifiedPolicyArtifact fails closed until D7 supplies the generated,
// tagged canonical artifact and private issuer marker.
func EmbeddedVerifiedPolicyArtifact() (VerifiedPolicyArtifact, error) {
	return VerifiedPolicyArtifact{}, contractError(ErrorCodeMissingSection)
}
