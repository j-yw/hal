//go:build linux && microvm_assets_integration

package minimalprofile

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMinimalRealExt4Production(t *testing.T) {
	requireImageTools(t)
	archive, pins := stagedFixture(t, nil)
	dir := privateDir(t)
	first, err := BuildImage(context.Background(), ImageRequest{Archive: archive, ArchiveSHA256: fileHash(t, archive), Output: filepath.Join(dir, "one.ext4"), Epoch: 1700000000, Pins: pins})
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildImage(context.Background(), ImageRequest{Archive: archive, ArchiveSHA256: fileHash(t, archive), Output: filepath.Join(dir, "two.ext4"), Epoch: 1700000000, Pins: pins})
	if err != nil {
		t.Fatal(err)
	}
	if first.RootfsSHA256 != second.RootfsSHA256 {
		t.Fatal("independent ext4 builds differ")
	}
	if len(first.Executables) != 4 || first.Inventory.Inodes < 15 || first.Inventory.LogicalBytes == 0 || first.Inventory.Findings == nil {
		t.Fatalf("incomplete measurements: %+v", first)
	}
	if first.InstalledPiTreeSHA256 != pins.InstalledPiTreeSHA256 {
		t.Fatal("installed dependency tree not measured")
	}
	if _, err := BuildImage(context.Background(), ImageRequest{Archive: archive, ArchiveSHA256: fileHash(t, archive), Output: filepath.Join(dir, "one.ext4"), Epoch: 1700000000, Pins: pins}); err == nil {
		t.Fatal("existing output overwritten")
	}
}

func TestMinimalImageRejectsUntrustedStage(t *testing.T) {
	requireImageTools(t)
	for _, scenario := range []string{"digest", "missing_tree_pin", "tree_tamper", "role_tamper", "credentials", "private_key", "privilege", "traversal", "symlink_parent", "historical_role", "wrong_workspace_uid", "untraversable_parent", "missing_agent", "duplicate", "oversize", "unlocked_root", "duplicate_workload"} {
		t.Run(scenario, func(t *testing.T) {
			archive, pins := stagedFixture(t, func(entries map[string]fixtureEntry) {
				switch scenario {
				case "unlocked_root":
					e := entries["etc/passwd"]
					e.data = strings.Replace(e.data, "root:x:", "root::", 1)
					entries["etc/passwd"] = e
				case "duplicate_workload":
					e := entries["etc/passwd"]
					e.data = "workload:x:0:0:Workload:/root:/bin/sh\n" + e.data
					entries["etc/passwd"] = e
				case "credentials":
					entries["etc/.npmrc"] = fixtureEntry{mode: 0600, data: "fixture token"}
				case "private_key":
					entries["etc/innocent"] = fixtureEntry{mode: 0600, data: "-----BEGIN OPENSSH PRIVATE KEY-----"}
				case "privilege":
					e := entries["usr/bin/node"]
					e.mode = 04755
					entries["usr/bin/node"] = e
				case "traversal":
					entries["../escape"] = fixtureEntry{mode: 0644, data: "escape"}
				case "symlink_parent":
					entries["usr"] = fixtureEntry{mode: 0777, link: "/tmp"}
				case "historical_role":
					entries["usr/bin/hal-guest-workload-shim"] = fixtureEntry{mode: 0755, data: "historical"}
				case "wrong_workspace_uid":
					e := entries["workspace"]
					e.uid = 998
					entries["workspace"] = e
				case "untraversable_parent":
					e := entries["usr"]
					e.mode = 0700
					entries["usr"] = e
				case "missing_agent":
					delete(entries, "usr/bin/hal-guest-agent")
				case "oversize":
					entries["large"] = fixtureEntry{mode: 0644, declared: 513 << 20}
				}
			})
			digest := fileHash(t, archive)
			switch scenario {
			case "digest":
				digest = strings.Repeat("a", 64)
			case "missing_tree_pin":
				pins.InstalledPiTreeSHA256 = ""
			case "tree_tamper":
				pins.InstalledPiTreeSHA256 = strings.Repeat("a", 64)
			case "role_tamper":
				pins.NodeSHA256 = strings.Repeat("a", 64)
			case "duplicate": // A second archive record must not replace the first.
				data, _ := os.ReadFile(archive)
				data = data[:len(data)-1024]
				var tail bytes.Buffer
				w := tar.NewWriter(&tail)
				_ = w.WriteHeader(&tar.Header{Name: "usr/bin/node", Mode: 0755, Size: 3})
				_, _ = w.Write([]byte("bad"))
				_ = w.Close()
				if err := os.WriteFile(archive, append(data, tail.Bytes()...), 0600); err != nil {
					t.Fatal(err)
				}
				digest = fileHash(t, archive)
			}
			out := filepath.Join(privateDir(t), "rootfs.ext4")
			_, err := BuildImage(context.Background(), ImageRequest{Archive: archive, ArchiveSHA256: digest, Output: out, Epoch: 1700000000, Pins: pins})
			if err == nil {
				t.Fatal("invalid image accepted")
			}
			if _, err := os.Lstat(out); !os.IsNotExist(err) {
				t.Fatal("failed build published output")
			}
		})
	}
}

func requireImageTools(t *testing.T) {
	t.Helper()
	for _, name := range []string{"mke2fs", "debugfs", "e2fsck"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Fatal("selected real ext4 fixture tool unavailable: " + name)
		}
	}
	if err := checkImageTools(context.Background()); err != nil {
		t.Fatal("selected real ext4 fixtures require e2fsprogs 1.47.4")
	}
}
