//go:build !l8_verified_pinned_callsite_evidence

package syscallpolicy

func EmbeddedExpectedPinnedCallsiteEvidence() (ExpectedPinnedCallsiteEvidence, error) {
	return ExpectedPinnedCallsiteEvidence{}, contractError(ErrorCodeMissingSection)
}
