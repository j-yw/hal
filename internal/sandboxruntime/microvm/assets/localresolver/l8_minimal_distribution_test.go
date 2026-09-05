package localresolver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	assetbuild "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/build"
)

func TestL8MinimalDistributionRequiresDistinctExplicitSelection(t *testing.T) {
	request := minimalDistributionFixture(t)
	verified, err := VerifyL8MinimalDistributionBundle(request)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = verified.Close() })
	descriptor, err := SelectL8MinimalDistribution(verified)
	if err != nil || descriptor.ID != "l8-minimal-credentials-image" {
		t.Fatalf("selection = %#v, %v", descriptor, err)
	}
	if _, err := VerifyDistributionBundle(request.DistributionRequest); err == nil {
		t.Fatal("generic verifier accepted minimal bundle")
	}
	if _, err := ResolveDistribution(request.DistributionRequest); err == nil {
		t.Fatal("generic resolver accepted minimal profile")
	}
	if _, err := VerifyL8DistributionBundle(L8DistributionRequest{DistributionRequest: request.DistributionRequest, ParentL7: request.ParentL7}); err == nil {
		t.Fatal("legacy L8 accepted minimal profile without its evidence")
	}
	if _, err := json.Marshal(verified); err == nil {
		t.Fatal("verified file ownership serialized")
	}
	if err := verified.Close(); err != nil {
		t.Fatal(err)
	}
	if err := verified.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := SelectL8MinimalDistribution(verified); err == nil {
		t.Fatal("closed selection accepted")
	}
	if _, err := SelectL8MinimalDistribution(VerifiedL8MinimalDistribution{}); err == nil {
		t.Fatal("zero authority accepted")
	}
}

func TestL8MinimalDistributionRejectsMissingCorruptAndRelabeledEvidence(t *testing.T) {
	for _, scenario := range []string{"missing_expected", "wrong_init", "wrong_agent", "wrong_workload", "wrong_rootfs", "wrong_source", "missing_parent", "other_parent", "parent_mutated", "missing_file", "extra_file", "corrupt_file", "symlink", "legacy_label", "l5_label", "unknown_field", "unknown_process", "privileged_binary", "incomplete_inventory"} {
		t.Run(scenario, func(t *testing.T) {
			request := minimalDistributionFixture(t)
			switch scenario {
			case "missing_expected":
				request.Expected = L8MinimalExpectedIdentity{}
			case "wrong_init":
				request.Expected.GuestInitSHA256 = strings.Repeat("a", 64)
			case "wrong_agent":
				request.Expected.GuestAgentSHA256 = strings.Repeat("a", 64)
			case "wrong_workload":
				request.Expected.Runtime.NodeSHA256 = strings.Repeat("a", 64)
			case "wrong_rootfs":
				request.Expected.RootfsSHA256 = strings.Repeat("a", 64)
			case "wrong_source":
				request.Expected.SourceRevision = strings.Repeat("a", 40)
			case "missing_parent":
				request.ParentL7 = VerifiedDistribution{}
			case "other_parent":
				request.ParentL7 = materializeVerifiedL7ParentFixture(t, "other-parent")
			case "parent_mutated":
				writeL5DistributionFile(t, request.ParentL7.rootDir, "rootfs.ext4", []byte("changed"))
			case "missing_file":
				if err := os.Remove(filepath.Join(request.RootDir, l8SourceLockName)); err != nil {
					t.Fatal(err)
				}
			case "extra_file":
				writeL5DistributionFile(t, request.RootDir, "unexpected", []byte("extra"))
			case "corrupt_file":
				writeL5DistributionFile(t, request.RootDir, "rootfs.ext4", []byte("changed"))
			case "symlink":
				name := filepath.Join(request.RootDir, "rootfs.ext4")
				if err := os.Rename(name, name+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(name+".saved", name); err != nil {
					t.Fatal(err)
				}
			default:
				minimalRewriteDocument(t, request.RootDir, distributionManifestName, func(document map[string]any) {
					switch scenario {
					case "legacy_label":
						document["imageProfile"] = assetbuild.ImageProfileL8ProductionCredentials
					case "l5_label":
						document["imageProfile"] = ""
					case "unknown_field":
						document["guestSeccomp"] = "active"
					}
				})
				if scenario == "unknown_process" || scenario == "privileged_binary" || scenario == "incomplete_inventory" {
					minimalRewriteDocument(t, request.RootDir, l8FinalInspectionName, func(document map[string]any) {
						if scenario == "incomplete_inventory" {
							document["inventory"].(map[string]any)["inodes"] = float64(0)
							return
						}
						executable := document["executables"].([]any)[0].(map[string]any)
						if scenario == "unknown_process" {
							executable["role"] = "credential-helper"
						} else {
							executable["mode"] = float64(04755)
						}
					})
				}
				minimalWriteChecksums(t, request.RootDir)
			}
			verified, err := VerifyL8MinimalDistributionBundle(request)
			if err == nil {
				_ = verified.Close()
				t.Fatal("invalid minimal bundle accepted")
			}
			if strings.Contains(err.Error(), request.RootDir) || strings.Contains(err.Error(), request.ParentL7.rootDir+"/") {
				t.Fatalf("unsafe error: %v", err)
			}
		})
	}
}

func TestL8MinimalSelectionRejectsReplacedRetainedFiles(t *testing.T) {
	for _, scenario := range []string{"child_asset", "child_metadata", "parent_asset", "parent_metadata", "child_root", "parent_root", "in_place"} {
		t.Run(scenario, func(t *testing.T) {
			request := minimalDistributionFixture(t)
			verified, err := VerifyL8MinimalDistributionBundle(request)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = verified.Close() })
			root, name := request.RootDir, "rootfs.ext4"
			if strings.HasPrefix(scenario, "parent_") {
				root = request.ParentL7.rootDir
			}
			if strings.HasSuffix(scenario, "metadata") {
				name = distributionManifestName
			}
			if strings.HasSuffix(scenario, "root") {
				if err := os.Rename(root, root+"-retained"); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.RemoveAll(root + "-retained") })
				if err := os.Mkdir(root, 0700); err != nil {
					t.Fatal(err)
				}
			} else if scenario == "in_place" {
				writeL5DistributionFile(t, root, name, []byte("changed"))
			} else {
				path := filepath.Join(root, name)
				data := l5ReadDistributionFile(t, path)
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				writeL5DistributionFile(t, root, name, data)
			}
			if _, err := SelectL8MinimalDistribution(verified); err == nil {
				t.Fatal("changed retained source accepted")
			}
		})
	}
}

func minimalDistributionFixture(t *testing.T) L8MinimalDistributionRequest {
	t.Helper()
	parent := materializeVerifiedL7ParentFixture(t, "minimal-parent")
	lease, err := parent.AcquireL7AssetLease()
	if err != nil {
		t.Fatal(err)
	}
	parentFacts, err := lease.measureL8ParentEvidence(parent.Manifest, parent.Provenance, parent.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	kernel := l5ReadDistributionFile(t, filepath.Join(parent.rootDir, "vmlinux"))
	rootfs := []byte("minimal fixture image; no runtime acceptance")
	runtime := assetbuild.L8RuntimeFacts{NodeVersion: "22.22.0", NodeSHA256: l5SHA256([]byte("node")), PiPackage: "@earendil-works/pi-coding-agent", PiVersion: "0.82.1", PiLauncherSHA256: l5SHA256([]byte("pi")), PiDependencyTreeSHA256: l5SHA256([]byte("dependency inventory"))}
	initDigest, agentDigest := l5SHA256([]byte("init")), l5SHA256([]byte("agent"))
	sources := assetbuild.L8MinimalSourceLock{SchemaVersion: assetbuild.L8MinimalSourceLockSchemaV1, ImageProfile: assetbuild.ImageProfileL8MinimalCredentials, SourceRevision: strings.Repeat("b", 40), ParentL7: parentFacts, Runtime: runtime, Sources: []assetbuild.L8LockedSource{
		{Kind: "node_source", Name: "node", Version: "22.22.0", Filename: "node.tar.gz", SizeBytes: 10, SHA256: l5SHA256([]byte("node source"))},
		{Kind: "pi_package", Name: "@earendil-works/pi-coding-agent", Version: "0.82.1", Filename: "pi.tgz", SizeBytes: 10, SHA256: l5SHA256([]byte("pi source"))},
		{Kind: "pi_shrinkwrap", Name: "pi-shrinkwrap", Version: "0.82.1", Filename: "shrinkwrap.json", SizeBytes: 10, SHA256: l5SHA256([]byte("shrinkwrap"))},
		{Kind: "npm_archive", Name: "dependency", Version: "1.2.3", Filename: "dependency.tgz", SizeBytes: 10, SHA256: l5SHA256([]byte("dependency source"))},
	}}
	runtime.PiDependencyTreeSHA256 = assetbuild.L8MinimalDependencyTreeSHA256(sources.Sources)
	sources.Runtime = runtime
	sourceBytes := minimalJSON(t, sources)
	inspection := assetbuild.L8MinimalFinalInspection{SchemaVersion: assetbuild.L8MinimalInspectionSchemaV1, ImageProfile: assetbuild.ImageProfileL8MinimalCredentials, SourceRevision: sources.SourceRevision, RootfsSHA256: l5SHA256(rootfs), SourceLockSHA256: l5SHA256(sourceBytes), ParentL7: parentFacts, Runtime: runtime,
		Executables: []assetbuild.L8MinimalExecutable{{Role: "hal-init", SHA256: initDigest, SizeBytes: 10, Mode: 0755}, {Role: "hal-guest-agent", SHA256: agentDigest, SizeBytes: 10, Mode: 0755}, {Role: "node", SHA256: runtime.NodeSHA256, SizeBytes: 10, Mode: 0755}, {Role: "pi-launcher", SHA256: runtime.PiLauncherSHA256, SizeBytes: 10, Mode: 0755}},
		Inventory:   assetbuild.L8MinimalInventory{Inodes: 20, DirectoryRecords: 30, LogicalBytes: 100}, AgentUID: 1000, WorkloadUID: 1000, WorkspaceUID: 1000, WorkspaceMode: 0700,
	}
	inspectionBytes := minimalJSON(t, inspection)
	profile := assetbuild.L8MinimalProfileFacts{ContractVersion: assetbuild.L8MinimalProfileContractV1, ParentL7: parentFacts, Runtime: runtime, GuestInitSHA256: initDigest, GuestAgentSHA256: agentDigest, SourceLockSHA256: l5SHA256(sourceBytes), FinalInspectionSHA256: l5SHA256(inspectionBytes)}
	manifest := assetbuild.L8MinimalDistributionManifest{SchemaVersion: assetbuild.SchemaVersionV1, ImageProfile: assetbuild.ImageProfileL8MinimalCredentials, Architecture: parent.Manifest.Architecture, Versions: parent.Manifest.Versions, GuestAgent: parent.Manifest.GuestAgent, GuestNetwork: parent.Manifest.GuestNetwork, MinimalProfile: profile, Assets: l5DistributionManifest(kernel, rootfs).Assets}
	provenance := assetbuild.L8MinimalProvenance{SchemaVersion: manifest.SchemaVersion, ImageProfile: manifest.ImageProfile, SourceRevision: sources.SourceRevision, SourceTree: "tree-0123456789abcdef", SourceDateEpoch: 1785024000, BuildImageDigest: "sha256:" + strings.Repeat("c", 64), Architecture: manifest.Architecture, Versions: manifest.Versions, GuestAgent: manifest.GuestAgent, GuestNetwork: manifest.GuestNetwork, MinimalProfile: profile}
	for _, asset := range manifest.Assets {
		provenance.Outputs = append(provenance.Outputs, assetbuild.Output{Key: asset.Key, ID: asset.ID, Kind: asset.Kind, SizeBytes: asset.SizeBytes, SHA256: asset.SHA256})
	}
	root := t.TempDir()
	for name, data := range map[string][]byte{distributionManifestName: minimalJSON(t, manifest), distributionProvenanceName: minimalJSON(t, provenance), l8SourceLockName: sourceBytes, l8FinalInspectionName: inspectionBytes, "vmlinux": kernel, "rootfs.ext4": rootfs} {
		writeL5DistributionFile(t, root, name, data)
	}
	minimalWriteChecksums(t, root)
	return L8MinimalDistributionRequest{DistributionRequest: DistributionRequest{RootDir: root, LockedAtUnixMillis: 1785024000000}, ParentL7: parent, Expected: L8MinimalExpectedIdentity{SourceRevision: sources.SourceRevision, RootfsSHA256: l5SHA256(rootfs), GuestInitSHA256: initDigest, GuestAgentSHA256: agentDigest, Runtime: runtime, SourceLockSHA256: profile.SourceLockSHA256, FinalInspectionSHA256: profile.FinalInspectionSHA256}}
}

func minimalJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func minimalWriteChecksums(t *testing.T, root string) {
	t.Helper()
	var output strings.Builder
	for _, name := range l8RequiredDistributionOutputs {
		if name != distributionChecksumsName {
			output.WriteString(l5SHA256(l5ReadDistributionFile(t, filepath.Join(root, name))) + "  " + name + "\n")
		}
	}
	writeL5DistributionFile(t, root, distributionChecksumsName, []byte(output.String()))
}
func minimalRewriteDocument(t *testing.T, root, name string, mutate func(map[string]any)) {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(l5ReadDistributionFile(t, filepath.Join(root, name)), &document); err != nil {
		t.Fatal(err)
	}
	mutate(document)
	writeL5DistributionFile(t, root, name, minimalJSON(t, document))
}
