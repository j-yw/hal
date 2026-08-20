package localresolver

import (
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/syscallpolicy"
)

// L8DistributionRequest carries the verified L8 bundle request, the live
// resolver-issued L7 parent authority, and the bounded generated HL8E bytes.
type L8DistributionRequest struct {
	DistributionRequest
	ParentL7               VerifiedDistribution
	PinnedCallsiteEvidence []byte
}

// VerifyL8DistributionBundle is the sole L8 profile issuer.
func VerifyL8DistributionBundle(request L8DistributionRequest) (VerifiedDistribution, error) {
	manifest, err := decodeL8DistributionManifest(request.DistributionRequest)
	if err != nil {
		return VerifiedDistribution{}, classifyL8DistributionManifestError(err)
	}
	provenance, err := decodeL8Provenance(request.DistributionRequest)
	if err != nil {
		return VerifiedDistribution{}, classifyL8ProvenanceError(err)
	}
	sourceLock, err := decodeL8SourceLock(request.DistributionRequest)
	if err != nil {
		return VerifiedDistribution{}, classifyL8SourceLockError(err)
	}
	finalInspection, err := decodeL8FinalInspection(request.DistributionRequest)
	if err != nil {
		return VerifiedDistribution{}, classifyL8FinalInspectionError(err)
	}
	parentL7Profile, ok := request.ParentL7.L7Profile()
	if !ok {
		return VerifiedDistribution{}, classifyL8ParentError(ErrAssetLockMismatch)
	}
	parentL7Lease, err := request.ParentL7.AcquireL7AssetLease()
	if err != nil {
		return VerifiedDistribution{}, classifyL8ParentError(err)
	}
	descriptor, rootDir, parentL7EvidenceSHA256, err := validateL8BundleState(request.DistributionRequest, manifest, provenance, sourceLock, finalInspection, request.ParentL7.Manifest, request.ParentL7.Provenance, request.ParentL7.Descriptor, request.ParentL7.rootDir, parentL7Profile, parentL7Lease)
	if err != nil {
		return VerifiedDistribution{}, classifyL8BundleStateError(err)
	}
	pinnedCallsiteEvidenceBytes, err := snapshotL8PinnedCallsiteEvidence(request.PinnedCallsiteEvidence)
	if err != nil {
		return VerifiedDistribution{}, classifyL8PinnedCallsiteEvidenceError(err)
	}
	defer wipeL8PinnedEvidence(pinnedCallsiteEvidenceBytes)
	artifact, err := syscallpolicy.EmbeddedVerifiedPolicyArtifact()
	if err != nil {
		return VerifiedDistribution{}, classifyL8PolicyArtifactError(err)
	}
	expectedEvidence, err := syscallpolicy.EmbeddedExpectedPinnedCallsiteEvidence()
	if err != nil {
		return VerifiedDistribution{}, classifyL8PinnedCallsiteEvidenceExpectationError(err)
	}
	evidence, err := syscallpolicy.ImportPinnedCallsiteEvidence(pinnedCallsiteEvidenceBytes, artifact, expectedEvidence)
	if err != nil {
		return VerifiedDistribution{}, classifyL8PinnedCallsiteEvidenceError(err)
	}
	manifestPolicyComposition, err := decodeL8PolicyCompositionDigests(manifest.L8Profile.ProcessComposition)
	if err != nil {
		return VerifiedDistribution{}, classifyL8PolicyCompositionDigestError(err)
	}
	provenancePolicyComposition, err := decodeL8PolicyCompositionDigests(provenance.L8Profile.ProcessComposition)
	if err != nil {
		return VerifiedDistribution{}, classifyL8PolicyCompositionDigestError(err)
	}
	finalInspectionPolicyComposition, err := decodeL8PolicyCompositionDigests(finalInspection.ProcessComposition)
	if err != nil {
		return VerifiedDistribution{}, classifyL8PolicyCompositionDigestError(err)
	}
	derivedPolicyComposition := deriveL8PolicyCompositionDigests(artifact, evidence)
	if err := validateL8PolicyCompositionCorrelation(derivedPolicyComposition, manifestPolicyComposition, provenancePolicyComposition, finalInspectionPolicyComposition); err != nil {
		return VerifiedDistribution{}, classifyL8PolicyCompositionCorrelationError(err)
	}
	evidenceFingerprint, imageSHA256, err := buildL8EvidenceFingerprint(request.DistributionRequest, manifest, provenance, sourceLock, finalInspection, parentL7EvidenceSHA256, derivedPolicyComposition)
	if err != nil {
		return VerifiedDistribution{}, classifyL8EvidenceFingerprintError(err)
	}
	descriptorFingerprint, err := buildL8DescriptorFingerprint(descriptor)
	if err != nil {
		return VerifiedDistribution{}, classifyL8ProfileSealError(err)
	}
	verifiedL8Profile, err := sealVerifiedL8Profile(descriptorFingerprint, evidenceFingerprint, imageSHA256, derivedPolicyComposition)
	if err != nil {
		return VerifiedDistribution{}, classifyL8ProfileSealError(err)
	}
	return sealVerifiedL8Distribution(verifiedL8Profile, evidenceFingerprint, derivedPolicyComposition, manifest, provenance, descriptor, rootDir), nil
}

func snapshotL8PinnedCallsiteEvidence(source []byte) ([]byte, error) {
	if len(source) == 0 || len(source) > l8MaxPinnedEvidenceBytes {
		return nil, ErrAssetLockMismatch
	}
	return append([]byte(nil), source...), nil
}

func wipeL8PinnedEvidence(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func classifyL8DistributionManifestError(_ error) error {
	return newResolverError(ErrorCodeManifestInvalid, "distributionManifest", "", "L8 distribution manifest is invalid", ErrManifestInvalid)
}

func classifyL8ProvenanceError(_ error) error {
	return newResolverError(ErrorCodeManifestInvalid, "provenance", "", "L8 provenance is invalid", ErrManifestInvalid)
}

func classifyL8SourceLockError(_ error) error {
	return newResolverError(ErrorCodeManifestInvalid, "sourceLock", "", "L8 source lock is invalid", ErrManifestInvalid)
}

func classifyL8FinalInspectionError(_ error) error {
	return newResolverError(ErrorCodeManifestInvalid, "finalInspection", "", "L8 final inspection is invalid", ErrManifestInvalid)
}

func classifyL8ParentError(_ error) error {
	return newResolverError(ErrorCodeAssetLockMismatch, "parentL7", "", "L8 parent distribution is not current", ErrAssetLockMismatch)
}

func classifyL8BundleStateError(_ error) error {
	return newResolverError(ErrorCodeAssetLockMismatch, "l8Profile", "", "L8 distribution correlation mismatch", ErrAssetLockMismatch)
}

func classifyL8PolicyArtifactError(_ error) error {
	return newResolverError(ErrorCodeAssetLockMismatch, "l8Profile", "", "L8 policy artifact is unavailable", ErrAssetLockMismatch)
}

func classifyL8PinnedCallsiteEvidenceExpectationError(_ error) error {
	return newResolverError(ErrorCodeAssetLockMismatch, "l8Profile", "", "L8 evidence expectation is unavailable", ErrAssetLockMismatch)
}

func classifyL8PinnedCallsiteEvidenceError(_ error) error {
	return newResolverError(ErrorCodeAssetLockMismatch, "l8Profile", "", "L8 pinned evidence is invalid", ErrAssetLockMismatch)
}

func classifyL8PolicyCompositionDigestError(_ error) error {
	return newResolverError(ErrorCodeManifestInvalid, "l8Profile", "", "L8 policy composition is invalid", ErrManifestInvalid)
}

func classifyL8PolicyCompositionCorrelationError(_ error) error {
	return newResolverError(ErrorCodeAssetLockMismatch, "processComposition", "", "L8 policy composition correlation mismatch", ErrAssetLockMismatch)
}

func classifyL8EvidenceFingerprintError(_ error) error {
	return newResolverError(ErrorCodeAssetLockMismatch, "l8Profile", "", "L8 evidence fingerprint is invalid", ErrAssetLockMismatch)
}

func classifyL8ProfileSealError(_ error) error {
	return newResolverError(ErrorCodeAssetLockMismatch, "l8Profile", "", "L8 profile seal is invalid", ErrAssetLockMismatch)
}
