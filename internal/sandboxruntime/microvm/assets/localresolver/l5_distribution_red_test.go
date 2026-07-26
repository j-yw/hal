package localresolver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
	assetbuild "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/build"
)

func TestL5ResolveDistributionVerifiesInstalledFilesBeforeMaterializingPaths(t *testing.T) {
	root := t.TempDir()
	kernel := []byte("deterministic-kernel")
	rootfs := []byte("deterministic-rootfs")
	writeL5DistributionFile(t, root, "vmlinux", kernel)
	writeL5DistributionFile(t, root, "rootfs.ext4", rootfs)
	writeL5DistributionManifest(t, root, l5DistributionManifest(kernel, rootfs))

	descriptor, err := ResolveDistribution(DistributionRequest{
		RootDir:            root,
		LockedAtUnixMillis: 1785024000000,
	})
	if err != nil {
		t.Fatalf("ResolveDistribution() error = %v", err)
	}
	if err := assets.ValidateLaunchDescriptor(descriptor); err != nil {
		t.Fatalf("ValidateLaunchDescriptor() error = %v", err)
	}
	if len(descriptor.Assets) != 2 {
		t.Fatalf("descriptor assets = %d, want 2", len(descriptor.Assets))
	}
	for _, asset := range descriptor.Assets {
		if asset.Source.Type != assets.SourceTypeLocalFile || asset.Source.HostPath == nil {
			t.Fatalf("asset source = %#v, want materialized local path", asset.Source)
		}
		if !filepath.IsAbs(asset.Source.HostPath.Path) {
			t.Fatalf("materialized path = %q, want absolute", asset.Source.HostPath.Path)
		}
		if !strings.HasPrefix(asset.Source.HostPath.Path, root+string(filepath.Separator)) {
			t.Fatalf("materialized path escaped distribution root")
		}
	}

	manifestBytes, err := os.ReadFile(filepath.Join(root, "distribution-manifest.json"))
	if err != nil {
		t.Fatalf("ReadFile(distribution-manifest.json) error = %v", err)
	}
	if strings.Contains(string(manifestBytes), root) {
		t.Fatal("distribution manifest contains runtime installation path")
	}
}

func TestL5ResolveDistributionFailsClosedOnInstalledAssetMismatch(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, root string)
	}{
		{
			name: "missing",
			mutate: func(t *testing.T, root string) {
				if err := os.Remove(filepath.Join(root, "vmlinux")); err != nil {
					t.Fatalf("Remove(vmlinux) error = %v", err)
				}
			},
		},
		{
			name: "digest",
			mutate: func(t *testing.T, root string) {
				writeL5DistributionFile(t, root, "vmlinux", []byte("same-size-bad-kernel"))
			},
		},
		{
			name: "size",
			mutate: func(t *testing.T, root string) {
				path := filepath.Join(root, "distribution-manifest.json")
				var manifest assetbuild.DistributionManifest
				if err := json.Unmarshal(l5ReadDistributionFile(t, path), &manifest); err != nil {
					t.Fatalf("Unmarshal(distribution-manifest.json) error = %v", err)
				}
				manifest.Assets[0].SizeBytes++
				writeL5DistributionManifest(t, root, manifest)
			},
		},
		{
			name: "symlink",
			mutate: func(t *testing.T, root string) {
				if err := os.Remove(filepath.Join(root, "vmlinux")); err != nil {
					t.Fatalf("Remove(vmlinux) error = %v", err)
				}
				if err := os.Symlink("rootfs.ext4", filepath.Join(root, "vmlinux")); err != nil {
					t.Fatalf("Symlink(vmlinux) error = %v", err)
				}
			},
		},
		{
			name: "nonregular",
			mutate: func(t *testing.T, root string) {
				if err := os.Remove(filepath.Join(root, "vmlinux")); err != nil {
					t.Fatalf("Remove(vmlinux) error = %v", err)
				}
				if err := os.Mkdir(filepath.Join(root, "vmlinux"), 0o700); err != nil {
					t.Fatalf("Mkdir(vmlinux) error = %v", err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			kernel := []byte("deterministic-kernel")
			rootfs := []byte("deterministic-rootfs")
			writeL5DistributionFile(t, root, "vmlinux", kernel)
			writeL5DistributionFile(t, root, "rootfs.ext4", rootfs)
			writeL5DistributionManifest(t, root, l5DistributionManifest(kernel, rootfs))
			tt.mutate(t, root)

			_, err := ResolveDistribution(DistributionRequest{RootDir: root})
			if err == nil {
				t.Fatal("ResolveDistribution() error = nil, want fail-closed error")
			}
			for _, leaked := range []string{root, "same-size-bad-kernel"} {
				if strings.Contains(err.Error(), leaked) {
					t.Fatalf("ResolveDistribution() error leaked private value")
				}
			}
		})
	}
}

func l5DistributionManifest(kernel, rootfs []byte) assetbuild.DistributionManifest {
	return assetbuild.DistributionManifest{
		SchemaVersion: assetbuild.SchemaVersionV1,
		Architecture:  "x86_64",
		Versions: assetbuild.Versions{
			Buildroot:   "2026.05.1",
			Linux:       "6.1.178",
			BusyBox:     "1.38.0",
			E2fsprogs:   "1.47.4",
			Go:          "1.25.7",
			Firecracker: "v1.15.1",
		},
		GuestAgent: assetbuild.GuestAgent{
			Protocol: "guest-agent-v1",
			Features: []string{"copy_in", "copy_out", "exec", "readiness"},
		},
		Assets: []assetbuild.DistributionAsset{
			{Key: "vmlinux", ID: "kernel", Kind: "kernel_image", SizeBytes: int64(len(kernel)), SHA256: l5SHA256(kernel)},
			{Key: "rootfs.ext4", ID: "rootfs", Kind: "rootfs_image", SizeBytes: int64(len(rootfs)), SHA256: l5SHA256(rootfs)},
		},
	}
}

func writeL5DistributionManifest(t *testing.T, root string, manifest assetbuild.DistributionManifest) {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal(manifest) error = %v", err)
	}
	writeL5DistributionFile(t, root, "distribution-manifest.json", append(data, '\n'))
}

func writeL5DistributionFile(t *testing.T, root, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), data, 0o600); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", name, err)
	}
}

func l5ReadDistributionFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(distribution) error = %v", err)
	}
	return data
}

func l5SHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
