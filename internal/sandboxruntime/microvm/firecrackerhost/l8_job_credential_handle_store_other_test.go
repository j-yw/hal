//go:build !linux

package firecrackerhost

import (
	"errors"
	"os"
	"testing"
)

func TestL8JobCredentialHandleStoreNonLinuxFailsClosedBeforeFiles(t *testing.T) {
	root := t.TempDir()
	store, err := NewProductionL8JobCredentialHandleStore(root)
	if store != nil || !errors.Is(err, ErrL8JobCredentialRuntimeUnsupported) {
		t.Fatalf("production constructor = %#v, %v", store, err)
	}
	entries, readErr := os.ReadDir(root)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("non-Linux constructor created files: %d", len(entries))
	}

	direct, openErr := openL8JobCredentialHandleStore(root)
	if direct != nil || !errors.Is(openErr, ErrL8JobCredentialRuntimeUnsupported) {
		t.Fatalf("openL8JobCredentialHandleStore = %#v, %v", direct, openErr)
	}
	entries, readErr = os.ReadDir(root)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("non-Linux open created files: %d", len(entries))
	}
}
