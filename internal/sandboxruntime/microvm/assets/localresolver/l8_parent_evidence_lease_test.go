package localresolver

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	assetbuild "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/build"
)

func TestL8ParentEvidenceRejectsRootSwapAfterPriorLeaseConfirmation(t *testing.T) {
	verified := materializeVerifiedL7ParentFixture(t, "trusted")
	lease, err := verified.AcquireL7AssetLease()
	if err != nil {
		t.Fatalf("AcquireL7AssetLease() error = %v", err)
	}
	t.Cleanup(func() { _ = lease.Close() })
	if err := lease.ConfirmCurrent(&verified.Descriptor); err != nil {
		t.Fatalf("ConfirmCurrent() error = %v", err)
	}

	trustedRoot := verified.rootDir
	movedRoot := trustedRoot + ".retained"
	if err := os.Rename(trustedRoot, movedRoot); err != nil {
		t.Fatalf("Rename(trusted root) error = %v", err)
	}
	attacker := materializeVerifiedL7ParentFixtureAt(t, trustedRoot, "attacker")

	_, err = lease.measureL8ParentEvidence(
		verified.Manifest,
		verified.Provenance,
		verified.Descriptor,
	)
	if !errors.Is(err, ErrAssetLockMismatch) {
		t.Fatalf("measureL8ParentEvidence() error = %v, want root-swap mismatch", err)
	}
	if attacker.rootDir != trustedRoot {
		t.Fatal("attacker fixture did not occupy the original parent path")
	}
}

func TestL8ParentEvidenceUsesCorrelatedLeaseRetainedFiles(t *testing.T) {
	verified := materializeVerifiedL7ParentFixture(t, "stable")
	lease, err := verified.AcquireL7AssetLease()
	if err != nil {
		t.Fatalf("AcquireL7AssetLease() error = %v", err)
	}
	t.Cleanup(func() { _ = lease.Close() })

	evidence, err := lease.measureL8ParentEvidence(
		verified.Manifest,
		verified.Provenance,
		verified.Descriptor,
	)
	if err != nil {
		t.Fatalf("measureL8ParentEvidence() error = %v", err)
	}
	if evidence.ImageProfile != assetbuild.ImageProfileL7Network ||
		evidence.KernelSHA256 != verified.Manifest.Assets[0].SHA256 ||
		evidence.RootfsSHA256 != verified.Manifest.Assets[1].SHA256 ||
		evidence.EvidenceSHA256 == "" {
		t.Fatalf("lease-retained evidence = %#v", evidence)
	}
}

func materializeVerifiedL7ParentFixture(t *testing.T, seed string) VerifiedDistribution {
	t.Helper()
	return materializeVerifiedL7ParentFixtureAt(t, filepath.Join(t.TempDir(), "distribution"), seed)
}

func materializeVerifiedL7ParentFixtureAt(t *testing.T, root, seed string) VerifiedDistribution {
	t.Helper()
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("MkdirAll(L7 root) error = %v", err)
	}
	kernel := []byte("l7-kernel-" + seed)
	rootfs := []byte("l7-rootfs-" + seed)
	manifest := l5DistributionManifest(kernel, rootfs)
	manifest.ImageProfile = assetbuild.ImageProfileL7Network
	manifest.GuestNetwork = &assetbuild.GuestNetwork{
		Mode:     assetbuild.GuestNetworkModeStaticProxy,
		Features: []string{"ipv4", "ipv6", "proxy_bootstrap", "virtio_net"},
	}
	provenance := assetbuild.Provenance{
		SchemaVersion:    assetbuild.SchemaVersionV1,
		ImageProfile:     manifest.ImageProfile,
		SourceRevision:   "762ee1a61d2efc5bb9241a6e87409ca20d68f976",
		SourceTree:       "tree-0123456789abcdef",
		SourceDateEpoch:  1785024000,
		BuildImageDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Architecture:     manifest.Architecture,
		Versions:         manifest.Versions,
		GuestAgent:       manifest.GuestAgent,
		GuestNetwork:     manifest.GuestNetwork,
		Outputs: []assetbuild.Output{
			{Key: manifest.Assets[0].Key, ID: manifest.Assets[0].ID, Kind: manifest.Assets[0].Kind, SizeBytes: manifest.Assets[0].SizeBytes, SHA256: manifest.Assets[0].SHA256},
			{Key: manifest.Assets[1].Key, ID: manifest.Assets[1].ID, Kind: manifest.Assets[1].Kind, SizeBytes: manifest.Assets[1].SizeBytes, SHA256: manifest.Assets[1].SHA256},
		},
	}
	writeL5DistributionFile(t, root, "vmlinux", kernel)
	writeL5DistributionFile(t, root, "rootfs.ext4", rootfs)
	writeL5DistributionManifest(t, root, manifest)
	provenanceBytes, err := json.Marshal(provenance)
	if err != nil {
		t.Fatalf("Marshal(L7 provenance) error = %v", err)
	}
	writeL5DistributionFile(t, root, distributionProvenanceName, append(provenanceBytes, '\n'))
	checksums := ""
	for _, name := range []string{distributionManifestName, distributionProvenanceName, "rootfs.ext4", "vmlinux"} {
		data, readErr := os.ReadFile(filepath.Join(root, name))
		if readErr != nil {
			t.Fatalf("ReadFile(%s) error = %v", name, readErr)
		}
		checksums += fmt.Sprintf("%s  %s\n", l5SHA256(data), name)
	}
	writeL5DistributionFile(t, root, distributionChecksumsName, []byte(checksums))
	verified, err := VerifyDistributionBundle(DistributionRequest{RootDir: root, LockedAtUnixMillis: 1785024000000})
	if err != nil {
		t.Fatalf("VerifyDistributionBundle(L7 fixture) error = %v", err)
	}
	return verified
}
