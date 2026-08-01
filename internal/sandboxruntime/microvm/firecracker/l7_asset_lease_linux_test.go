//go:build linux

package firecracker

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
)

func TestVerifiedL7AssetLeaseClosesAllPinnedDescriptors(t *testing.T) {
	verified := verifiedL7DistributionForTest(t)
	baseline := l7OpenDescriptorCount(t)
	for iteration := 0; iteration < 32; iteration++ {
		lease, err := verified.AcquireL7AssetLease()
		if err != nil {
			t.Fatalf("AcquireL7AssetLease(%d) error = %v", iteration, err)
		}
		if err := lease.Close(); err != nil {
			t.Fatalf("Close(%d) error = %v", iteration, err)
		}
	}
	if got := l7OpenDescriptorCount(t); got != baseline {
		t.Fatalf("open descriptor count = %d, want baseline %d after lease cleanup", got, baseline)
	}
}

func TestSealedL7LaunchMaterialClosePreservesSanitizedOSCause(t *testing.T) {
	kernel, err := os.CreateTemp(t.TempDir(), "private-kernel-")
	if err != nil {
		t.Fatal(err)
	}
	rootfs, err := os.CreateTemp(t.TempDir(), "private-rootfs-")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range []*os.File{kernel, rootfs} {
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	material := &sealedL7LaunchMaterial{assets: map[assets.AssetRole]*sealedL7Asset{
		assets.AssetRoleKernel: {file: kernel},
		assets.AssetRoleRootfs: {file: rootfs},
	}}
	firstCloseErr := material.Close()
	secondCloseErr := material.Close()
	if firstCloseErr == nil || firstCloseErr != secondCloseErr {
		t.Fatalf("repeated Close errors = (%v, %v), want one stable cleanup error", firstCloseErr, secondCloseErr)
	}
	var pathErr *os.PathError
	if !errors.As(firstCloseErr, &pathErr) || pathErr == nil {
		t.Fatalf("errors.As(Close error, *os.PathError) = false, want original OS close cause")
	}
	for _, private := range []string{kernel.Name(), rootfs.Name()} {
		if strings.Contains(firstCloseErr.Error(), private) {
			t.Fatalf("Close error leaked private path %q: %v", private, firstCloseErr)
		}
	}
}

func l7OpenDescriptorCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("ReadDir(/proc/self/fd) error = %v", err)
	}
	return len(entries)
}
