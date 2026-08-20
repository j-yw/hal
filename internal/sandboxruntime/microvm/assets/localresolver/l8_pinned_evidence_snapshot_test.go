package localresolver

import (
	"errors"
	"testing"
)

func TestSnapshotL8PinnedCallsiteEvidenceBoundsBeforeCopy(t *testing.T) {
	for _, input := range [][]byte{
		nil,
		{},
		make([]byte, l8MaxPinnedEvidenceBytes+1),
	} {
		if snapshot, err := snapshotL8PinnedCallsiteEvidence(input); snapshot != nil || !errors.Is(err, ErrAssetLockMismatch) {
			t.Fatalf("snapshotL8PinnedCallsiteEvidence(len=%d) = (%d bytes, %v), want nil/asset-lock mismatch", len(input), len(snapshot), err)
		}
	}

	input := []byte("bounded-evidence")
	snapshot, err := snapshotL8PinnedCallsiteEvidence(input)
	if err != nil {
		t.Fatalf("snapshotL8PinnedCallsiteEvidence() error = %v", err)
	}
	input[0] ^= 0xff
	if string(snapshot) != "bounded-evidence" {
		t.Fatal("snapshot aliases caller-owned evidence")
	}
}
