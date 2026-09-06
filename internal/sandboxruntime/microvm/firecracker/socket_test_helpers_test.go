package firecracker

import (
	"os"
	"testing"
)

func firecrackerShortSocketTestRoot(t *testing.T) string {
	t.Helper()

	root, err := os.MkdirTemp("/tmp", "hal-fc-")
	if err != nil {
		t.Fatal("create short Firecracker test state root failed")
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error("remove short Firecracker test state root failed")
		}
	})
	return root
}
