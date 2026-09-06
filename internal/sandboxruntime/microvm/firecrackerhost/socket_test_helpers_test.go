package firecrackerhost

import (
	"os"
	"testing"
)

func firecrackerHostShortSocketTestRoot(t *testing.T) string {
	t.Helper()

	root, err := os.MkdirTemp("/tmp", "hal-fc-host-")
	if err != nil {
		t.Fatal("create short Firecracker host socket test directory")
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error("remove short Firecracker host socket test directory")
		}
	})
	return root
}
