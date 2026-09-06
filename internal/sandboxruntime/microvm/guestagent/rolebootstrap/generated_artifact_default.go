//go:build !l8_verified_native_artifact

package rolebootstrap

// EmbeddedGeneratedArtifact fails closed until the tagged D7 native issuer
// supplies the exact native source, callsite, and install-table identities.
func EmbeddedGeneratedArtifact() (GeneratedArtifact, error) {
	return GeneratedArtifact{}, ErrDependency
}
