package localresolver

import (
	"crypto/subtle"

	assetbuild "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/build"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy"
)

type l8VerifiedPolicyCompositionDigests struct {
	workloadSnapshotSHA256       [32]byte
	runtimeProfileSHA256         [32]byte
	policyArtifactSHA256         [32]byte
	policySourceLockSHA256       [32]byte
	policyBinaryBindingSetSHA256 [32]byte
	pinnedCallsiteEvidenceSHA256 [32]byte
}

func deriveL8PolicyCompositionDigests(
	artifact syscallpolicy.VerifiedPolicyArtifact,
	evidence syscallpolicy.PinnedCallsiteEvidenceSet,
) l8VerifiedPolicyCompositionDigests {
	return l8VerifiedPolicyCompositionDigests{
		workloadSnapshotSHA256:       artifact.Workload().SHA256(),
		runtimeProfileSHA256:         artifact.Runtime().SHA256(),
		policyArtifactSHA256:         artifact.SHA256(),
		policySourceLockSHA256:       artifact.SourceLockSHA256(),
		policyBinaryBindingSetSHA256: evidence.BinaryBindings().SHA256(),
		pinnedCallsiteEvidenceSHA256: evidence.SHA256(),
	}
}

func l8PolicyCompositionDigestsEqual(left, right l8VerifiedPolicyCompositionDigests) bool {
	matches := 1
	matches &= subtle.ConstantTimeCompare(left.workloadSnapshotSHA256[:], right.workloadSnapshotSHA256[:])
	matches &= subtle.ConstantTimeCompare(left.runtimeProfileSHA256[:], right.runtimeProfileSHA256[:])
	matches &= subtle.ConstantTimeCompare(left.policyArtifactSHA256[:], right.policyArtifactSHA256[:])
	matches &= subtle.ConstantTimeCompare(left.policySourceLockSHA256[:], right.policySourceLockSHA256[:])
	matches &= subtle.ConstantTimeCompare(left.policyBinaryBindingSetSHA256[:], right.policyBinaryBindingSetSHA256[:])
	matches &= subtle.ConstantTimeCompare(left.pinnedCallsiteEvidenceSHA256[:], right.pinnedCallsiteEvidenceSHA256[:])
	return matches == 1
}

func validateL8PolicyCompositionCorrelation(
	derived, manifest, provenance, finalInspection l8VerifiedPolicyCompositionDigests,
) error {
	if !l8PolicyCompositionDigestsEqual(derived, manifest) {
		return l8PolicyCompositionCorrelationMismatch()
	}
	if !l8PolicyCompositionDigestsEqual(derived, provenance) {
		return l8PolicyCompositionCorrelationMismatch()
	}
	if !l8PolicyCompositionDigestsEqual(derived, finalInspection) {
		return l8PolicyCompositionCorrelationMismatch()
	}
	return nil
}

func validateL8DocumentPolicyCompositionCorrelation(
	manifest, provenance, finalInspection assetbuild.L8ProcessCompositionFacts,
) error {
	manifestDigests, err := decodeL8PolicyCompositionDigests(manifest)
	if err != nil {
		return err
	}
	provenanceDigests, err := decodeL8PolicyCompositionDigests(provenance)
	if err != nil {
		return err
	}
	finalInspectionDigests, err := decodeL8PolicyCompositionDigests(finalInspection)
	if err != nil {
		return err
	}
	if !l8PolicyCompositionDigestsEqual(manifestDigests, provenanceDigests) ||
		!l8PolicyCompositionDigestsEqual(manifestDigests, finalInspectionDigests) {
		return l8PolicyCompositionCorrelationMismatch()
	}
	return nil
}

func l8PolicyCompositionCorrelationMismatch() error {
	return &assetbuild.L8ValidationError{
		Code:  assetbuild.L8ValidationCode("correlation_mismatch"),
		Field: "processComposition",
	}
}
