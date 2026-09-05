//go:build !l8_verified_native_artifact

package rolebootstrap

import (
	"errors"
	"testing"
)

func TestEmbeddedGeneratedArtifactIsUnavailableByDefault(t *testing.T) {
	artifact, err := EmbeddedGeneratedArtifact()
	if artifact != (GeneratedArtifact{}) || !errors.Is(err, ErrDependency) {
		t.Fatalf("EmbeddedGeneratedArtifact() = %#v, %v", artifact, err)
	}
}
