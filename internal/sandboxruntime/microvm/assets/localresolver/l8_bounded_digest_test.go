package localresolver

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	assetbuild "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/build"
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

func TestResolveL8DistributionFromRootRejectsOversizedReplacementBeforeReading(t *testing.T) {
	rootPath := t.TempDir()
	kernel := []byte("bounded-kernel")
	rootfs := []byte("bounded-rootfs")
	writeL5DistributionFile(t, rootPath, "vmlinux", kernel)
	writeL5DistributionFile(t, rootPath, "rootfs.ext4", rootfs)
	manifest := l5DistributionManifest(kernel, rootfs)
	manifest.ImageProfile = assetbuild.ImageProfileL8ProductionCredentials

	replacement, err := os.Create(filepath.Join(rootPath, "rootfs.ext4.replacement"))
	if err != nil {
		t.Fatal(err)
	}
	if err := replacement.Truncate(l8MaxPinnedAssetBytes + 1); err != nil {
		_ = replacement.Close()
		t.Fatal(err)
	}
	if err := replacement.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(rootPath, "rootfs.ext4.replacement"), filepath.Join(rootPath, "rootfs.ext4")); err != nil {
		t.Fatal(err)
	}
	root, err := os.Open(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })

	_, err = resolveL8DistributionFromRoot(root, rootPath, 1, manifest)
	if !errors.Is(err, ErrAssetLockMismatch) {
		t.Fatalf("resolveL8DistributionFromRoot() error = %v, want bounded mismatch", err)
	}
}

func TestResolveL8DistributionFromRootRejectsTrailingBytesAgainstExpectedSize(t *testing.T) {
	rootPath := t.TempDir()
	kernel := []byte("bounded-kernel")
	rootfs := []byte("bounded-rootfs")
	writeL5DistributionFile(t, rootPath, "vmlinux", kernel)
	writeL5DistributionFile(t, rootPath, "rootfs.ext4", append(append([]byte(nil), rootfs...), '!'))
	manifest := l5DistributionManifest(kernel, rootfs)
	manifest.ImageProfile = assetbuild.ImageProfileL8ProductionCredentials
	root, err := os.Open(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })

	_, err = resolveL8DistributionFromRoot(root, rootPath, 1, manifest)
	if !errors.Is(err, ErrAssetLockMismatch) {
		t.Fatalf("resolveL8DistributionFromRoot() error = %v, want trailing-byte mismatch", err)
	}
}
