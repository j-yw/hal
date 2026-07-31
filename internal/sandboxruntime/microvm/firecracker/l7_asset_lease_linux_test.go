//go:build linux

package firecracker

import (
	"os"
	"testing"
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

func l7OpenDescriptorCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("ReadDir(/proc/self/fd) error = %v", err)
	}
	return len(entries)
}
