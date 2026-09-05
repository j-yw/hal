package localresolver

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
)

func TestMeasurePinnedL8FileIsBoundedAndExact(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "asset-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	content := []byte("verified-l8-asset")
	if _, err := file.Write(content); err != nil {
		t.Fatal(err)
	}

	size, digest, err := measurePinnedL8File(file)
	if err != nil {
		t.Fatalf("measurePinnedL8File() error = %v", err)
	}
	if size != int64(len(content)) || digest != sha256.Sum256(content) {
		t.Fatal("measurePinnedL8File() returned the wrong measurement")
	}
	position, err := file.Seek(0, 1)
	if err != nil || position != 0 {
		t.Fatal("measurePinnedL8File() did not rewind the retained file")
	}

	empty, err := os.CreateTemp(t.TempDir(), "empty-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = empty.Close() })
	if _, _, err := measurePinnedL8File(empty); !errors.Is(err, ErrAssetLockMismatch) {
		t.Fatalf("empty file error = %v, want asset-lock mismatch", err)
	}

	oversized, err := os.CreateTemp(t.TempDir(), "oversized-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = oversized.Close() })
	if err := oversized.Truncate(l8MaxPinnedAssetBytes + 1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := measurePinnedL8File(oversized); !errors.Is(err, ErrAssetLockMismatch) {
		t.Fatalf("oversized file error = %v, want asset-lock mismatch", err)
	}
}

func TestL8LaunchMaterialCallbacksContainPanics(t *testing.T) {
	material := panicL8LaunchMaterial{}
	if _, err := writeL8LaunchMaterialAsset(material, assets.AssetRoleKernel, strings.NewReader("kernel")); !errors.Is(err, ErrFileUnavailable) {
		t.Fatalf("WriteAsset panic error = %v, want unavailable", err)
	}
	if err := validateL8LaunchMaterial(material); !errors.Is(err, ErrAssetLockMismatch) {
		t.Fatalf("Validate panic error = %v, want asset mismatch", err)
	}
	if err := closeL8LaunchMaterial(material); !errors.Is(err, ErrFileUnavailable) {
		t.Fatalf("Close panic error = %v, want unavailable", err)
	}
}

type panicL8LaunchMaterial struct{}

func (panicL8LaunchMaterial) WriteAsset(assets.AssetRole, io.Reader) (string, error) {
	panic("private write panic")
}

func (panicL8LaunchMaterial) Validate() error {
	panic("private validation panic")
}

func (panicL8LaunchMaterial) Close() error {
	panic("private close panic")
}

func TestL8CleanupErrorRetainsCauseWithoutLeakingIt(t *testing.T) {
	privateCause := errors.New("private cleanup path /tmp/l8-secret")
	err := l8CleanupError(privateCause)
	if !errors.Is(err, ErrFileUnavailable) || !errors.Is(err, privateCause) {
		t.Fatal("cleanup error did not retain both stable and underlying causes")
	}
	if strings.Contains(err.Error(), privateCause.Error()) || strings.Contains(err.Error(), "/tmp/") {
		t.Fatalf("cleanup error leaked its private cause: %v", err)
	}
}
