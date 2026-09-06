//go:build !linux

package credentialsource

import (
	"errors"
	"testing"
)

func TestL8CredentialSourceNonLinuxProductionConstructorFailsClosed(t *testing.T) {
	registry, err := NewRegistry(RegistryConfig{})
	if registry != nil || !errors.Is(err, ErrCredentialSourceUnsupported) {
		t.Fatal("non-Linux credential source constructor did not fail closed")
	}
}
