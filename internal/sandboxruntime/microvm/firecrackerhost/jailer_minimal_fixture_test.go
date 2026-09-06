package firecrackerhost

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	assetbuild "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/build"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/localresolver"
)

// Synthetic file bytes exercise the real bundle issuer and stager. They are
// deliberately not ext4, executable, source-build, or guest-boot evidence.
func minimalJailerFixture(t *testing.T) (localresolver.VerifiedL8MinimalDistribution, string, []byte, []byte) {
	t.Helper()
	kernel, parentRootfs, rootfs := []byte("fixture kernel"), []byte("fixture parent rootfs"), []byte("fixture minimal rootfs")
	marshal := func(value any) []byte {
		t.Helper()
		b, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	assets := func(kernel, rootfs []byte) []assetbuild.DistributionAsset {
		return []assetbuild.DistributionAsset{{Key: "vmlinux", ID: "kernel", Kind: "kernel_image", SizeBytes: int64(len(kernel)), SHA256: sha256Hex(kernel)}, {Key: "rootfs.ext4", ID: "rootfs", Kind: "rootfs_image", SizeBytes: int64(len(rootfs)), SHA256: sha256Hex(rootfs)}}
	}
	outputs := func(input []assetbuild.DistributionAsset) []assetbuild.Output {
		var result []assetbuild.Output
		for _, asset := range input {
			result = append(result, assetbuild.Output{Key: asset.Key, ID: asset.ID, Kind: asset.Kind, SizeBytes: asset.SizeBytes, SHA256: asset.SHA256})
		}
		return result
	}
	write := func(root string, files map[string][]byte) {
		t.Helper()
		var names []string
		for name := range files {
			names = append(names, name)
		}
		sort.Strings(names)
		var checksums strings.Builder
		for _, name := range names {
			if err := os.WriteFile(filepath.Join(root, name), files[name], 0600); err != nil {
				t.Fatal(err)
			}
			checksums.WriteString(sha256Hex(files[name]) + "  " + name + "\n")
		}
		if err := os.WriteFile(filepath.Join(root, "SHA256SUMS"), []byte(checksums.String()), 0600); err != nil {
			t.Fatal(err)
		}
	}
	parentManifest := assetbuild.DistributionManifest{SchemaVersion: assetbuild.SchemaVersionV1, ImageProfile: assetbuild.ImageProfileL7Network, Architecture: "x86_64",
		Versions:     assetbuild.Versions{Buildroot: "2026.05.1", Linux: "6.1.178", BusyBox: "1.38.0", E2fsprogs: "1.47.4", Go: "1.25.7", Firecracker: "v1.15.1"},
		GuestAgent:   assetbuild.GuestAgent{Protocol: "guest-agent-v1", Features: []string{"copy_in", "copy_out", "exec", "readiness"}},
		GuestNetwork: &assetbuild.GuestNetwork{Mode: assetbuild.GuestNetworkModeStaticProxy, Features: []string{"ipv4", "ipv6", "proxy_bootstrap", "virtio_net"}}, Assets: assets(kernel, parentRootfs)}
	parentProvenance := assetbuild.Provenance{SchemaVersion: parentManifest.SchemaVersion, ImageProfile: parentManifest.ImageProfile, SourceRevision: strings.Repeat("b", 40), SourceTree: "tree-0123456789abcdef", SourceDateEpoch: 1785024000, BuildImageDigest: "sha256:" + strings.Repeat("c", 64), Architecture: parentManifest.Architecture, Versions: parentManifest.Versions, GuestAgent: parentManifest.GuestAgent, GuestNetwork: parentManifest.GuestNetwork, Outputs: outputs(parentManifest.Assets)}
	parentDir := t.TempDir()
	write(parentDir, map[string][]byte{"distribution-manifest.json": marshal(parentManifest), "provenance.json": marshal(parentProvenance), "vmlinux": kernel, "rootfs.ext4": parentRootfs})
	parent, err := localresolver.VerifyDistributionBundle(localresolver.DistributionRequest{RootDir: parentDir})
	if err != nil {
		t.Fatal(err)
	}
	checksums, err := os.ReadFile(filepath.Join(parentDir, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	parentFacts := assetbuild.L8ParentL7Evidence{ImageProfile: assetbuild.ImageProfileL7Network, ManifestSHA256: sha256Hex(marshal(parentManifest)), ProvenanceSHA256: sha256Hex(marshal(parentProvenance)), ChecksumsSHA256: sha256Hex(checksums), KernelSizeBytes: int64(len(kernel)), KernelSHA256: sha256Hex(kernel), RootfsSizeBytes: int64(len(parentRootfs)), RootfsSHA256: sha256Hex(parentRootfs)}
	hash := sha256.New()
	for _, token := range []string{"hal/l8/image-profile/parent-l7-evidence/v1", assetbuild.ImageProfileL7Network} {
		_ = binary.Write(hash, binary.BigEndian, uint16(len(token)))
		hash.Write([]byte(token))
	}
	for _, digest := range []string{parentFacts.ManifestSHA256, parentFacts.ProvenanceSHA256, parentFacts.ChecksumsSHA256} {
		raw, _ := hex.DecodeString(digest)
		hash.Write(raw)
	}
	_ = binary.Write(hash, binary.BigEndian, uint64(parentFacts.KernelSizeBytes))
	raw, _ := hex.DecodeString(parentFacts.KernelSHA256)
	hash.Write(raw)
	_ = binary.Write(hash, binary.BigEndian, uint64(parentFacts.RootfsSizeBytes))
	raw, _ = hex.DecodeString(parentFacts.RootfsSHA256)
	hash.Write(raw)
	parentFacts.EvidenceSHA256 = hex.EncodeToString(hash.Sum(nil))
	initDigest, agentDigest := sha256Hex([]byte("init")), sha256Hex([]byte("agent"))
	runtime := assetbuild.L8RuntimeFacts{NodeVersion: "22.22.0", NodeSHA256: sha256Hex([]byte("node")), PiPackage: "@earendil-works/pi-coding-agent", PiVersion: "0.82.1", PiLauncherSHA256: sha256Hex([]byte("pi"))}
	sources := assetbuild.L8MinimalSourceLock{SchemaVersion: assetbuild.L8MinimalSourceLockSchemaV1, ImageProfile: assetbuild.ImageProfileL8MinimalCredentials, SourceRevision: parentProvenance.SourceRevision, ParentL7: parentFacts, Sources: []assetbuild.L8LockedSource{
		{Kind: "node_source", Name: "node", Version: "22.22.0", Filename: "node.tar.gz", SizeBytes: 10, SHA256: sha256Hex([]byte("node source"))},
		{Kind: "pi_package", Name: runtime.PiPackage, Version: "0.82.1", Filename: "pi.tgz", SizeBytes: 10, SHA256: sha256Hex([]byte("pi source"))},
		{Kind: "pi_shrinkwrap", Name: "pi-shrinkwrap", Version: "0.82.1", Filename: "shrinkwrap.json", SizeBytes: 10, SHA256: sha256Hex([]byte("shrinkwrap"))},
		{Kind: "npm_archive", Name: "dependency", Version: "1.2.3", Filename: "dependency.tgz", SizeBytes: 10, SHA256: sha256Hex([]byte("dependency"))}}}
	runtime.PiDependencyTreeSHA256 = assetbuild.L8MinimalDependencyTreeSHA256(sources.Sources)
	sources.Runtime = runtime
	inspection := assetbuild.L8MinimalFinalInspection{SchemaVersion: assetbuild.L8MinimalInspectionSchemaV1, ImageProfile: sources.ImageProfile, SourceRevision: sources.SourceRevision, RootfsSHA256: sha256Hex(rootfs), SourceLockSHA256: sha256Hex(marshal(sources)), ParentL7: parentFacts, Runtime: runtime,
		Executables: []assetbuild.L8MinimalExecutable{{Role: "hal-init", SHA256: initDigest, SizeBytes: 10, Mode: 0755}, {Role: "hal-guest-agent", SHA256: agentDigest, SizeBytes: 10, Mode: 0755}, {Role: "node", SHA256: runtime.NodeSHA256, SizeBytes: 10, Mode: 0755}, {Role: "pi-launcher", SHA256: runtime.PiLauncherSHA256, SizeBytes: 10, Mode: 0755}},
		Inventory:   assetbuild.L8MinimalInventory{Inodes: 20, DirectoryRecords: 30, LogicalBytes: 100, Findings: []string{}}, AgentUID: 1000, WorkloadUID: 1000, WorkspaceUID: 1000, WorkspaceMode: 0700}
	for i := range inspection.Executables {
		inspection.Executables[i].Type = "regular"
		inspection.Executables[i].UID = new(uint32)
		inspection.Executables[i].GID = new(uint32)
	}
	profile := assetbuild.L8MinimalProfileFacts{ContractVersion: assetbuild.L8MinimalProfileContractV1, ParentL7: parentFacts, Runtime: runtime, GuestInitSHA256: initDigest, GuestAgentSHA256: agentDigest, SourceLockSHA256: sha256Hex(marshal(sources)), FinalInspectionSHA256: sha256Hex(marshal(inspection))}
	manifest := assetbuild.L8MinimalDistributionManifest{SchemaVersion: parentManifest.SchemaVersion, ImageProfile: sources.ImageProfile, Architecture: parentManifest.Architecture, Versions: parentManifest.Versions, GuestAgent: parentManifest.GuestAgent, GuestNetwork: parentManifest.GuestNetwork, MinimalProfile: profile, Assets: assets(kernel, rootfs)}
	provenance := assetbuild.L8MinimalProvenance{SchemaVersion: manifest.SchemaVersion, ImageProfile: manifest.ImageProfile, SourceRevision: sources.SourceRevision, SourceTree: parentProvenance.SourceTree, SourceDateEpoch: parentProvenance.SourceDateEpoch, BuildImageDigest: parentProvenance.BuildImageDigest, Architecture: manifest.Architecture, Versions: manifest.Versions, GuestAgent: manifest.GuestAgent, GuestNetwork: manifest.GuestNetwork, MinimalProfile: profile, Outputs: outputs(manifest.Assets)}
	root := t.TempDir()
	write(root, map[string][]byte{"distribution-manifest.json": marshal(manifest), "provenance.json": marshal(provenance), "sources.lock.json": marshal(sources), "final-inspection.json": marshal(inspection), "vmlinux": kernel, "rootfs.ext4": rootfs})
	verified, err := localresolver.VerifyL8MinimalDistributionBundle(localresolver.L8MinimalDistributionRequest{DistributionRequest: localresolver.DistributionRequest{RootDir: root}, ParentL7: parent, Expected: localresolver.L8MinimalExpectedIdentity{SourceRevision: sources.SourceRevision, RootfsSHA256: sha256Hex(rootfs), GuestInitSHA256: initDigest, GuestAgentSHA256: agentDigest, Runtime: runtime, SourceLockSHA256: profile.SourceLockSHA256, FinalInspectionSHA256: profile.FinalInspectionSHA256, ProvenanceSHA256: sha256Hex(marshal(provenance))}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = verified.Close() })
	return verified, root, kernel, rootfs
}
