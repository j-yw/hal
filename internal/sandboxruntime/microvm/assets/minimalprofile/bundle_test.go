//go:build linux

package minimalprofile

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	assetbuild "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/build"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/localresolver"
)

func TestMinimalSevenFilePublisher(t *testing.T) {
	requireImageTools(t)
	req := bundleFixture(t)
	receipt, err := Publish(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(req.OutputDir)
	if err != nil || len(files) != 7 {
		t.Fatalf("bundle entries=%v err=%v", files, err)
	}
	parent, err := localresolver.VerifyDistributionBundle(localresolver.DistributionRequest{RootDir: req.ParentDir})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := localresolver.VerifyL8MinimalDistributionBundle(localresolver.L8MinimalDistributionRequest{DistributionRequest: localresolver.DistributionRequest{RootDir: req.OutputDir}, ParentL7: parent, Expected: receipt.Expected})
	if err != nil {
		t.Fatal(err)
	}
	defer verified.Close()
	if _, err := localresolver.SelectL8MinimalDistribution(verified); err != nil {
		t.Fatal(err)
	}
	if _, err := localresolver.VerifyDistributionBundle(localresolver.DistributionRequest{RootDir: req.OutputDir}); err == nil {
		t.Fatal("generic launch authority issued")
	}
	second := req
	second.OutputDir = filepath.Join(filepath.Dir(req.OutputDir), "second")
	again, err := Publish(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	if receipt != again {
		t.Fatal("receipt differs between independent builds")
	}
	for _, file := range files {
		if fileHash(t, filepath.Join(req.OutputDir, file.Name())) != fileHash(t, filepath.Join(second.OutputDir, file.Name())) {
			t.Fatalf("nonreproducible %s", file.Name())
		}
	}
	if _, err := Publish(context.Background(), req); err == nil {
		t.Fatal("existing bundle overwritten")
	}
}

func TestMinimalPublisherRejectsUnprovenInputs(t *testing.T) {
	requireImageTools(t)
	for _, scenario := range []string{"source_tamper", "missing_source", "unissued_parent", "changed_parent", "untrusted_tree", "builder_identity", "revision", "missing_stage", "wrong_runtime_version"} {
		t.Run(scenario, func(t *testing.T) {
			req := bundleFixture(t)
			switch scenario {
			case "source_tamper":
				if err := os.WriteFile(filepath.Join(req.SourceDir, req.Sources[3].Filename), []byte("tampered"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing_source":
				req.Sources[3].Filename = "missing.tgz"
			case "unissued_parent":
				req.ParentDir = privateDir(t)
			case "changed_parent":
				if err := os.WriteFile(filepath.Join(req.ParentDir, "vmlinux"), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "untrusted_tree":
				req.Pins.InstalledPiTreeSHA256 = ""
			case "builder_identity":
				req.BuildImageDigest = ""
			case "revision":
				req.SourceRevision = "unknown"
			case "missing_stage":
				req.Archive = filepath.Join(privateDir(t), "absent.tar")
			case "wrong_runtime_version":
				req.Sources[0].Version = "20.0.0"
			}
			if _, err := Publish(context.Background(), req); err == nil {
				t.Fatal("unproven bundle published")
			}
			if _, err := os.Lstat(req.OutputDir); !os.IsNotExist(err) {
				t.Fatal("partial bundle published")
			}
		})
	}
}

// These tiny data files exercise resolver-issued correlation, not a genuine
// production kernel, Node installation, source closure or boot acceptance.
func bundleFixture(t *testing.T) PublishRequest {
	t.Helper()
	archive, pins := stagedFixture(t, nil)
	parent := privateDir(t)
	versions := assetbuild.Versions{Buildroot: "2026.05.1", Linux: "6.1.178", BusyBox: "1.38.0", E2fsprogs: "1.47.4", Go: "1.25.7", Firecracker: "v1.15.1"}
	agent := assetbuild.GuestAgent{Protocol: "guest-agent-v1", Features: []string{"copy_in", "copy_out", "exec", "readiness"}}
	network := &assetbuild.GuestNetwork{Mode: "static_proxy", Features: []string{"ipv4", "ipv6", "proxy_bootstrap", "virtio_net"}}
	m := assetbuild.DistributionManifest{SchemaVersion: assetbuild.SchemaVersionV1, ImageProfile: assetbuild.ImageProfileL7Network, Architecture: "x86_64", Versions: versions, GuestAgent: agent, GuestNetwork: network}
	p := assetbuild.Provenance{SchemaVersion: m.SchemaVersion, ImageProfile: m.ImageProfile, SourceRevision: strings.Repeat("a", 40), SourceTree: "tree-" + strings.Repeat("b", 40), SourceDateEpoch: 1700000000, BuildImageDigest: BuilderImageDigest, Architecture: m.Architecture, Versions: versions, GuestAgent: agent, GuestNetwork: network}
	for _, name := range []string{"vmlinux", "rootfs.ext4"} {
		data := []byte("fixture parent " + name)
		if err := os.WriteFile(filepath.Join(parent, name), data, 0600); err != nil {
			t.Fatal(err)
		}
		id, kind := "kernel", "kernel_image"
		if name == "rootfs.ext4" {
			id, kind = "rootfs", "rootfs_image"
		}
		m.Assets = append(m.Assets, assetbuild.DistributionAsset{Key: name, ID: id, Kind: kind, SizeBytes: int64(len(data)), SHA256: hash(data)})
		p.Outputs = append(p.Outputs, assetbuild.Output{Key: name, ID: id, Kind: kind, SizeBytes: int64(len(data)), SHA256: hash(data)})
	}
	writeJSONFixture(t, parent, "distribution-manifest.json", m)
	writeJSONFixture(t, parent, "provenance.json", p)
	var checksums strings.Builder
	for _, name := range []string{"distribution-manifest.json", "provenance.json", "rootfs.ext4", "vmlinux"} {
		fmt.Fprintf(&checksums, "%s  %s\n", fileHash(t, filepath.Join(parent, name)), name)
	}
	if err := os.WriteFile(filepath.Join(parent, "SHA256SUMS"), []byte(checksums.String()), 0600); err != nil {
		t.Fatal(err)
	}
	sourceDir := privateDir(t)
	sources := []assetbuild.L8LockedSource{{Kind: "node_source", Name: "node", Version: "22.22.0", Filename: "node.tar.gz"}, {Kind: "pi_package", Name: "@earendil-works/pi-coding-agent", Version: "0.82.1", Filename: "pi.tgz"}, {Kind: "pi_shrinkwrap", Name: "pi-shrinkwrap", Version: "0.82.1", Filename: "shrinkwrap.json"}, {Kind: "npm_archive", Name: "dependency", Version: "1.0.0", Filename: "dependency.tgz"}}
	for i := range sources {
		data := []byte("fixture source " + sources[i].Name)
		sources[i].SHA256 = hash(data)
		sources[i].SizeBytes = int64(len(data))
		if err := os.WriteFile(filepath.Join(sourceDir, sources[i].Filename), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return PublishRequest{ParentDir: parent, SourceDir: sourceDir, OutputDir: filepath.Join(privateDir(t), "bundle"), SourceRevision: strings.Repeat("c", 40), SourceTree: "tree-" + strings.Repeat("d", 40), Epoch: 1700000000, BuildImageDigest: BuilderImageDigest, Archive: archive, ArchiveSHA256: fileHash(t, archive), Pins: pins, Sources: sources}
}
func writeJSONFixture(t *testing.T, root, name string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, name), append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}
