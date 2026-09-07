//go:build linux && microvm_assets_integration

package minimalprofile

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Actual unprivileged ext4 production, not a native compile, mount or guest
// execution. The baseline is an independently executed control. At RED the
// applet case fails extraction before its later measured-inode assertions.
func TestMinimalBusyboxRealExt4(t *testing.T) {
	requireImageTools(t)
	var baseline Measurement
	for _, applets := range []bool{false, true} {
		name := "baseline"
		if applets {
			name = "applets"
		}
		t.Run(name, func(t *testing.T) {
			archive, pins := stagedFixture(t, func(entries map[string]fixtureEntry) {
				if !applets {
					return
				}
				for _, name := range []string{"usr/bin/[", "usr/bin/[["} {
					entries[name] = fixtureEntry{mode: 0777, link: "../../bin/busybox"}
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			output := filepath.Join(privateDir(t), "rootfs.ext4")
			result, err := BuildImage(ctx, ImageRequest{Archive: archive, ArchiveSHA256: fileHash(t, archive), Output: output, Epoch: 1700000000, Pins: pins})
			if err != nil {
				if _, statErr := os.Lstat(output); !os.IsNotExist(statErr) {
					t.Fatal("failed image build published output", statErr)
				}
				t.Fatal("actual bounded ext4 producer rejected selected applets", err)
			}
			if len(result.Executables) != 4 || result.InstalledPiTreeSHA256 != pins.InstalledPiTreeSHA256 || result.Inventory.Findings == nil {
				t.Fatal("ext4 measurement lost unchanged pins/inventory")
			}
			if !applets {
				baseline = result
			} else if result.Inventory.Inodes != baseline.Inventory.Inodes+2 || result.Inventory.DirectoryRecords != baseline.Inventory.DirectoryRecords+2 || result.Inventory.LogicalBytes != baseline.Inventory.LogicalBytes {
				t.Fatal("real image did not preserve exactly the two additional applet inodes/records")
			}
		})
	}
}
