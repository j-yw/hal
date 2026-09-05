//go:build l8_verified_policy_artifact && l8_verified_pinned_callsite_evidence

package localresolver

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	assetbuild "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/build"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy"
)

func buildCompleteValidL8DistributionRequestFixture(t *testing.T) L8DistributionRequest {
	t.Helper()
	artifact, err := syscallpolicy.EmbeddedVerifiedPolicyArtifact()
	if err != nil {
		t.Fatalf("load generated HL8Q fixture authority: %v", err)
	}
	expectedEvidence, err := syscallpolicy.EmbeddedExpectedPinnedCallsiteEvidence()
	if err != nil {
		t.Fatalf("load generated HL8E fixture authority: %v", err)
	}
	evidenceBytes := readGeneratedL8PinnedEvidenceFixture(t)
	evidence, err := syscallpolicy.ImportPinnedCallsiteEvidence(evidenceBytes, artifact, expectedEvidence)
	if err != nil {
		t.Fatalf("import generated HL8E fixture: %v", err)
	}

	parent := materializeVerifiedL7ParentFixture(t, "l8-parent")
	parentLease, err := parent.AcquireL7AssetLease()
	if err != nil {
		t.Fatalf("acquire real L7 parent authority: %v", err)
	}
	parentEvidence, measureErr := parentLease.measureL8ParentEvidence(parent.Manifest, parent.Provenance, parent.Descriptor)
	closeErr := parentLease.Close()
	if measureErr != nil || closeErr != nil {
		t.Fatalf("measure real L7 parent authority: %v", errors.Join(measureErr, closeErr))
	}

	composition := l8FixtureProcessComposition(artifact, evidence)
	sources := l8FixtureLockedSources()
	runtimeFacts := assetbuild.L8RuntimeFacts{
		NodeVersion:            "22.22.0",
		NodeSHA256:             l8FixtureSHA256("node-runtime"),
		PiPackage:              "@earendil-works/pi-coding-agent",
		PiVersion:              "0.82.1",
		PiLauncherSHA256:       l8FixtureSHA256("pi-launcher"),
		PiDependencyTreeSHA256: l8FixturePiDependencyTreeSHA256(sources),
	}
	sourceLock := assetbuild.L8SourceLock{
		SchemaVersion:  assetbuild.L8SourceLockSchemaVersionV1,
		CatalogVersion: assetbuild.L8SourceLockCatalogVersionV1,
		ImageProfile:   assetbuild.ImageProfileL8ProductionCredentials,
		ParentL7:       parentEvidence,
		Runtime:        runtimeFacts,
		Sources:        sources,
	}
	sourceLockBytes := marshalL8FixtureDocument(t, sourceLock)

	rootfs := []byte("complete-correlated-l8-rootfs")
	kernel := []byte("complete-correlated-l8-kernel")
	inspection := assetbuild.L8FinalInspection{
		SchemaVersion:      assetbuild.L8FinalInspectionSchemaVersionV1,
		CatalogVersion:     assetbuild.L8FinalInspectionCatalogVersionV1,
		ImageProfile:       assetbuild.ImageProfileL8ProductionCredentials,
		RootfsSHA256:       l5SHA256(rootfs),
		SourceLockSHA256:   l5SHA256(sourceLockBytes),
		ParentL7:           parentEvidence,
		Runtime:            runtimeFacts,
		ProcessComposition: composition,
		Checks:             l8FixtureInspectionChecks(),
	}
	inspectionBytes := marshalL8FixtureDocument(t, inspection)
	profile := assetbuild.L8ProfileFacts{
		ContractVersion:       assetbuild.L8ProfileContractVersionV1,
		ParentL7:              parentEvidence,
		Runtime:               runtimeFacts,
		ProcessComposition:    composition,
		SourceLockSHA256:      l5SHA256(sourceLockBytes),
		FinalInspectionSHA256: l5SHA256(inspectionBytes),
	}
	manifest := assetbuild.DistributionManifest{
		SchemaVersion: assetbuild.SchemaVersionV1,
		ImageProfile:  assetbuild.ImageProfileL8ProductionCredentials,
		Architecture:  "x86_64",
		Versions: assetbuild.Versions{
			Buildroot: "2026.05.1", Linux: "6.1.178", BusyBox: "1.38.0",
			E2fsprogs: "1.47.4", Go: "1.25.7", Firecracker: "v1.15.1",
		},
		GuestAgent: assetbuild.GuestAgent{
			Protocol: assetbuild.L8GuestAgentProtocolV2,
			Features: []string{"copy_in", "copy_out", "credential_delivery_v2", "exec", "readiness", "ssh_agent_relay_v1"},
		},
		GuestNetwork: &assetbuild.GuestNetwork{
			Mode:     assetbuild.GuestNetworkModeStaticProxy,
			Features: []string{"ipv4", "ipv6", "proxy_bootstrap", "virtio_net"},
		},
		L8Profile: &profile,
		Assets: []assetbuild.DistributionAsset{
			{Key: "vmlinux", ID: "kernel", Kind: "kernel_image", SizeBytes: int64(len(kernel)), SHA256: l5SHA256(kernel)},
			{Key: "rootfs.ext4", ID: "rootfs", Kind: "rootfs_image", SizeBytes: int64(len(rootfs)), SHA256: l5SHA256(rootfs)},
		},
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
		L8Profile:        &profile,
		Outputs: []assetbuild.Output{
			{Key: "vmlinux", ID: "kernel", Kind: "kernel_image", SizeBytes: int64(len(kernel)), SHA256: l5SHA256(kernel)},
			{Key: "rootfs.ext4", ID: "rootfs", Kind: "rootfs_image", SizeBytes: int64(len(rootfs)), SHA256: l5SHA256(rootfs)},
		},
	}

	root := t.TempDir()
	writeL5DistributionFile(t, root, distributionManifestName, marshalL8FixtureDocument(t, manifest))
	writeL5DistributionFile(t, root, l8FinalInspectionName, inspectionBytes)
	writeL5DistributionFile(t, root, distributionProvenanceName, marshalL8FixtureDocument(t, provenance))
	writeL5DistributionFile(t, root, "rootfs.ext4", rootfs)
	writeL5DistributionFile(t, root, l8SourceLockName, sourceLockBytes)
	writeL5DistributionFile(t, root, "vmlinux", kernel)
	if err := rewriteL8FixtureChecksums(DistributionRequest{RootDir: root}); err != nil {
		t.Fatalf("write L8 fixture checksums: %v", err)
	}
	return L8DistributionRequest{
		DistributionRequest:    DistributionRequest{RootDir: root, LockedAtUnixMillis: 1785024000000},
		ParentL7:               parent,
		PinnedCallsiteEvidence: append([]byte(nil), evidenceBytes...),
	}
}

func rewriteExactL8PolicyCompositionField(request DistributionRequest, document, field, replacement string) error {
	if !validDistributionDigest(replacement) {
		return ErrAssetLockMismatch
	}
	name := ""
	var composition *assetbuild.L8ProcessCompositionFacts
	var value any
	switch document {
	case "manifest":
		var manifest assetbuild.DistributionManifest
		if err := readL8FixtureDocument(request, distributionManifestName, &manifest); err != nil || manifest.L8Profile == nil {
			return ErrManifestInvalid
		}
		name, composition, value = distributionManifestName, &manifest.L8Profile.ProcessComposition, &manifest
	case "provenance":
		var provenance assetbuild.Provenance
		if err := readL8FixtureDocument(request, distributionProvenanceName, &provenance); err != nil || provenance.L8Profile == nil {
			return ErrManifestInvalid
		}
		name, composition, value = distributionProvenanceName, &provenance.L8Profile.ProcessComposition, &provenance
	case "finalInspection":
		var inspection assetbuild.L8FinalInspection
		if err := readL8FixtureDocument(request, l8FinalInspectionName, &inspection); err != nil {
			return ErrManifestInvalid
		}
		name, composition, value = l8FinalInspectionName, &inspection.ProcessComposition, &inspection
	default:
		return ErrInvalidRequest
	}
	if !replaceExactL8CompositionDigest(composition, field, replacement) {
		return ErrInvalidRequest
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return ErrManifestInvalid
	}
	encoded = append(encoded, '\n')
	if err := writeL8FixtureDocument(request, name, encoded); err != nil {
		return err
	}
	if err := rewriteL8FixtureChecksums(request); err != nil {
		return err
	}
	var rechecked map[string]any
	if err := readL8FixtureDocument(request, name, &rechecked); err != nil {
		return err
	}
	return nil
}

func replaceExactL8CompositionDigest(composition *assetbuild.L8ProcessCompositionFacts, field, replacement string) bool {
	if composition == nil {
		return false
	}
	switch field {
	case "workloadSnapshotSha256":
		composition.WorkloadSnapshotSHA256 = replacement
	case "runtimeProfileSha256":
		composition.RuntimeProfileSHA256 = replacement
	case "policyArtifactSha256":
		composition.PolicyArtifactSHA256 = replacement
	case "policySourceLockSha256":
		composition.PolicySourceLockSHA256 = replacement
	case "policyBinaryBindingSetSha256":
		composition.PolicyBinaryBindingSetSHA256 = replacement
	case "pinnedCallsiteEvidenceSha256":
		composition.PinnedCallsiteEvidenceSHA256 = replacement
	default:
		return false
	}
	return true
}

func readGeneratedL8PinnedEvidenceFixture(t *testing.T) []byte {
	t.Helper()
	_, sourcePath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate L8 fixture source")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(sourcePath), "..", "..", "..", "..", ".."))
	path := filepath.Join(repositoryRoot, "tools", "microvm", "l8", "policy", "verified-pinned-callsites.hl8e")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > syscallpolicy.MaxPinnedCallsiteEvidenceBytes {
		t.Fatal("generated HL8E fixture is unavailable or invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal("open generated HL8E fixture")
	}
	defer file.Close()
	encoded, err := io.ReadAll(io.LimitReader(file, syscallpolicy.MaxPinnedCallsiteEvidenceBytes+1))
	if err != nil || int64(len(encoded)) != info.Size() {
		t.Fatal("read generated HL8E fixture")
	}
	return encoded
}

func l8FixtureProcessComposition(
	artifact syscallpolicy.VerifiedPolicyArtifact,
	evidence syscallpolicy.PinnedCallsiteEvidenceSet,
) assetbuild.L8ProcessCompositionFacts {
	derived := deriveL8PolicyCompositionDigests(artifact, evidence)
	return assetbuild.L8ProcessCompositionFacts{
		CatalogVersion:   assetbuild.L8ProcessCompositionCatalogV1,
		GuestAgentSHA256: l8FixtureSHA256("guest-agent"), GuestInitSHA256: l8FixtureSHA256("guest-init"),
		CredentialHelperSHA256: l8FixtureSHA256("credential-helper"), MountMonitorSHA256: l8FixtureSHA256("mount-monitor"),
		WorkloadShimSHA256: l8FixtureSHA256("workload-shim"), RoleBootstrapSHA256: l8FixtureSHA256("role-bootstrap"),
		HelperDescriptorSHA256: l8FixtureSHA256("helper-descriptor"), ClientDescriptorSHA256: l8FixtureSHA256("client-descriptor"),
		CompositionSHA256:            l8FixtureSHA256("composition"),
		WorkloadSnapshotSHA256:       hex.EncodeToString(derived.workloadSnapshotSHA256[:]),
		RuntimeProfileSHA256:         hex.EncodeToString(derived.runtimeProfileSHA256[:]),
		PolicyArtifactSHA256:         hex.EncodeToString(derived.policyArtifactSHA256[:]),
		PolicySourceLockSHA256:       hex.EncodeToString(derived.policySourceLockSHA256[:]),
		PolicyBinaryBindingSetSHA256: hex.EncodeToString(derived.policyBinaryBindingSetSHA256[:]),
		PinnedCallsiteEvidenceSHA256: hex.EncodeToString(derived.pinnedCallsiteEvidenceSHA256[:]),
	}
}

func l8FixtureLockedSources() []assetbuild.L8LockedSource {
	return []assetbuild.L8LockedSource{
		{Kind: "node_source", Name: "node", Version: "22.22.0", Filename: "node-v22.22.0.tar.xz", SizeBytes: 101, SHA256: l8FixtureSHA256("source-node")},
		{Kind: "pi_package", Name: "@earendil-works/pi-coding-agent", Version: "0.82.1", Filename: "pi-coding-agent-0.82.1.tgz", SizeBytes: 102, SHA256: l8FixtureSHA256("source-pi")},
		{Kind: "pi_shrinkwrap", Name: "pi-shrinkwrap", Version: "0.82.1", Filename: "pi-shrinkwrap-0.82.1.json", SizeBytes: 103, SHA256: l8FixtureSHA256("source-shrinkwrap")},
		{Kind: "npm_archive", Name: "fixture-dependency", Version: "1.0.0", Filename: "fixture-dependency-1.0.0.tgz", SizeBytes: 104, SHA256: l8FixtureSHA256("source-dependency")},
	}
}

func l8FixturePiDependencyTreeSHA256(sources []assetbuild.L8LockedSource) string {
	var preimage bytes.Buffer
	l8WriteToken(&preimage, "hal/l8/pi-dependency-tree/v1")
	writeSource := func(source assetbuild.L8LockedSource) {
		l8WriteToken(&preimage, source.Kind)
		l8WriteToken(&preimage, source.Name)
		l8WriteToken(&preimage, source.Version)
		l8WriteToken(&preimage, source.Filename)
		l8WriteUint64(&preimage, uint64(source.SizeBytes))
		digest, _ := hex.DecodeString(source.SHA256)
		preimage.Write(digest)
	}
	for _, source := range sources[1:3] {
		writeSource(source)
	}
	if err := binary.Write(&preimage, binary.BigEndian, uint32(len(sources)-3)); err != nil {
		return ""
	}
	for _, source := range sources[3:] {
		writeSource(source)
	}
	return l5SHA256(preimage.Bytes())
}

func l8FixtureInspectionChecks() []assetbuild.L8InspectionCheck {
	ids := []string{
		"parent_l7_profile", "kernel_network_profile", "guest_binary_inventory", "binary_owner_mode",
		"node_runtime", "pi_runtime", "pi_dependency_tree", "offline_source_inventory",
		"package_manager_state_absent", "credential_material_absent", "identity_layout", "pid1_launch_order",
		"process_composition", "workload_snapshot", "runtime_profile", "policy_artifact", "native_bootstrap",
		"vsock_listener_table", "filesystem_privilege_absent", "filesystem_private_modes",
		"kernel_tmpfs_mount_namespace", "kernel_cgroup_v2_kill",
	}
	checks := make([]assetbuild.L8InspectionCheck, len(ids))
	for index, id := range ids {
		checks[index] = assetbuild.L8InspectionCheck{ID: id, Status: "pass", EvidenceSHA256: l8FixtureSHA256(fmt.Sprintf("inspection-%02d-%s", index, id))}
	}
	return checks
}

func l8FixtureSHA256(value string) string {
	digest := sha256.Sum256([]byte("hal/l8/fixture/" + value))
	return hex.EncodeToString(digest[:])
}

func marshalL8FixtureDocument(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal L8 fixture document: %v", err)
	}
	return append(encoded, '\n')
}

func readL8FixtureDocument(request DistributionRequest, name string, destination any) error {
	root, _, err := openRequestedDistributionRoot(request.RootDir)
	if err != nil {
		return err
	}
	defer root.Close()
	return decodeL8DistributionJSONFromRoot(root, name, destination)
}

func writeL8FixtureDocument(request DistributionRequest, name string, encoded []byte) error {
	root, cleanRoot, err := openRequestedDistributionRoot(request.RootDir)
	if err != nil {
		return err
	}
	if err := root.Close(); err != nil {
		return ErrFileUnavailable
	}
	path := filepath.Join(cleanRoot, name)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ErrFileUnavailable
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return ErrFileUnavailable
	}
	return nil
}

func rewriteL8FixtureChecksums(request DistributionRequest) error {
	root, cleanRoot, err := openRequestedDistributionRoot(request.RootDir)
	if err != nil {
		return err
	}
	defer root.Close()
	var output strings.Builder
	for _, name := range []string{distributionManifestName, l8FinalInspectionName, distributionProvenanceName, "rootfs.ext4", l8SourceLockName, "vmlinux"} {
		_, digest, err := digestL8DistributionFile(root, name)
		if err != nil {
			return err
		}
		fmt.Fprintf(&output, "%s  %s\n", digest, name)
	}
	path := filepath.Join(cleanRoot, distributionChecksumsName)
	if info, err := os.Lstat(path); err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return ErrFileUnavailable
	}
	if err := os.WriteFile(path, []byte(output.String()), 0o600); err != nil {
		return ErrFileUnavailable
	}
	return nil
}
