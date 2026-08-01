//go:build linux

package firecracker

import (
	"os"
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
	t.Cleanup(func() {
		for _, file := range []*os.File{kernel, rootfs} {
			if err := file.Close(); err != nil {
				t.Errorf("Close(%s) error = %v", file.Name(), err)
			}
		}
	})
	firstCloseFailure := &l7FirstCleanupFailure{detail: "private kernel close detail"}
	secondCloseFailure := &l7SecondCleanupFailure{detail: "private rootfs close detail"}
	closeCalls := 0
	material := &sealedL7LaunchMaterial{assets: map[assets.AssetRole]*sealedL7Asset{
		assets.AssetRoleKernel: {file: kernel},
		assets.AssetRoleRootfs: {file: rootfs},
	}, closeFile: func(file *os.File) error {
		closeCalls++
		if file == kernel {
			return firstCloseFailure
		}
		return secondCloseFailure
	}}
	firstCloseErr := material.Close()
	secondCloseErr := material.Close()
	if firstCloseErr == nil || firstCloseErr != secondCloseErr {
		t.Fatalf("repeated Close errors = (%v, %v), want one stable cleanup error", firstCloseErr, secondCloseErr)
	}
	assertL7CleanupCauses(t, firstCloseErr, firstCloseFailure, secondCloseFailure)
	if closeCalls != 2 {
		t.Fatalf("close calls = %d, want two once-only attempts", closeCalls)
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
