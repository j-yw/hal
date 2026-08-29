//go:build !l8_verified_pinned_callsite_evidence

package syscallpolicy

import "testing"

func TestPinnedCallsiteEvidenceDefaultExpectationIsUnavailable(t *testing.T) {
	t.Parallel()

	expected, err := EmbeddedExpectedPinnedCallsiteEvidence()
	if expected.SHA256() != ([32]byte{}) || contractErrorCode(err) != ErrorCodeMissingSection {
		t.Fatalf("EmbeddedExpectedPinnedCallsiteEvidence() = (%x, %v), want zero/missing-section", expected.SHA256(), err)
	}
}
