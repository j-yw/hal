//go:build linux && microvm_assets_integration

package minimalprofile

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestMinimalNativeContentRealExt4(t *testing.T) {
	requireImageTools(t)
	for _, tc := range []struct {
		name, content string
		accepted      bool
	}{
		{"baseline", "module.exports = 'independent ext4 control';\n", true},
		{"placeholder", nativeContentPlaceholder, true},
		{"type_check", nativeContentTypeCheck, true},
		{"mixed_assignment", nativeContentPlaceholder + "_authToken=synthetic-value\n", false},
		{"mixed_canary", nativeContentTypeCheck + "; HAL_CONTENT_CANARY", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			archive, pins := nativeContentFixture(t, tc.content)
			output := filepath.Join(privateDir(t), "content.ext4")
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			result, err := BuildImage(ctx, ImageRequest{Archive: archive, ArchiveSHA256: fileHash(t, archive), Output: output, Epoch: 1700000000, Pins: pins})
			if tc.accepted {
				if err != nil {
					t.Fatalf("bounded real ext4 rejected harmless fixture: %v", err)
				}
				if result.InstalledPiTreeSHA256 != pins.InstalledPiTreeSHA256 || len(result.Executables) != 4 || result.RootfsSHA256 != fileHash(t, output) {
					t.Fatal("complete actual-byte measurement missing")
				}
			} else {
				if err == nil || err.Error() != "minimal image: ext4 inspection rejected" || !reflect.DeepEqual(result, Measurement{}) {
					t.Fatalf("content rejection did not reach actual ext4 inspection: %v", err)
				}
				if _, err := os.Lstat(output); !os.IsNotExist(err) {
					t.Fatal("failed content scan published output")
				}
			}
		})
	}
}
