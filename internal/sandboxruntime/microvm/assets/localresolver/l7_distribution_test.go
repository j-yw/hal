package localresolver

import (
	"testing"

	assetbuild "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/build"
)

func TestL7ResolveDistributionPreservesOnlySafeProfileIdentity(t *testing.T) {
	root := t.TempDir()
	kernel := []byte("deterministic-l7-kernel")
	rootfs := []byte("deterministic-l7-rootfs")
	writeL5DistributionFile(t, root, "vmlinux", kernel)
	writeL5DistributionFile(t, root, "rootfs.ext4", rootfs)
	manifest := l5DistributionManifest(kernel, rootfs)
	manifest.ImageProfile = assetbuild.ImageProfileL7Network
	manifest.GuestNetwork = &assetbuild.GuestNetwork{
		Mode:     assetbuild.GuestNetworkModeStaticProxy,
		Features: []string{"ipv4", "ipv6", "proxy_bootstrap", "virtio_net"},
	}
	writeL5DistributionManifest(t, root, manifest)

	descriptor, err := ResolveDistribution(DistributionRequest{RootDir: root})
	if err != nil {
		t.Fatalf("ResolveDistribution() error = %v", err)
	}
	if descriptor.ID != "l7-network-image" {
		t.Fatalf("descriptor.ID = %q, want l7-network-image", descriptor.ID)
	}
	if len(descriptor.Labels) != 3 || descriptor.Labels[2] != "network-profile" {
		t.Fatalf("descriptor.Labels = %#v, want safe L7 profile label", descriptor.Labels)
	}
}
