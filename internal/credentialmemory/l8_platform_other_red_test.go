//go:build !linux

package credentialmemory

import (
	"errors"
	"testing"
)

func TestL8CredentialMemoryNonLinuxProductionConstructorsFailClosed(t *testing.T) {
	mapping, err := NewLockedMapping(32)
	if mapping != nil || !errors.Is(err, ErrCredentialMemoryUnsupported) {
		t.Fatal("non-Linux locked mapping constructor did not fail closed")
	}
	if err := HardenCredentialProcess(); !errors.Is(err, ErrCredentialMemoryUnsupported) {
		t.Fatal("non-Linux credential process hardening did not fail closed")
	}
}
