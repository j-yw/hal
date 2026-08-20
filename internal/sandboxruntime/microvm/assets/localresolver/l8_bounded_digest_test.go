package localresolver

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDigestL8DistributionFileEnforcesPerFileBoundsBeforeReading(t *testing.T) {
	rootPath := t.TempDir()
	write := func(name string, size int64) {
		t.Helper()
		file, err := os.Create(filepath.Join(rootPath, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(size); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	write("vmlinux", l8MaxPinnedAssetBytes+1)
	write(distributionManifestName, l8MaxMetadataBytes+1)
	write("rootfs.ext4", 2)
	root, err := os.Open(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })

	for _, name := range []string{"vmlinux", distributionManifestName} {
		if _, _, err := digestL8DistributionFile(root, name); !errors.Is(err, ErrAssetLockMismatch) {
			t.Fatalf("digestL8DistributionFile(%q) error = %v, want bounded mismatch", name, err)
		}
	}
	if size, digest, err := digestL8DistributionFile(root, "rootfs.ext4"); err != nil || size != 2 || len(digest) != 64 {
		t.Fatalf("small rootfs measurement = (%d, %q, %v), want exact digest", size, digest, err)
	}
}
