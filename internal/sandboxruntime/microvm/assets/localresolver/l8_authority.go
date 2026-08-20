package localresolver

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"sync"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
	assetbuild "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/build"
)

type verifiedL8ProfileSeal struct {
	active bool
}

type verifiedL8PolicyAuthorityBindings struct {
	policyArtifactSHA256         [32]byte
	policySourceLockSHA256       [32]byte
	policyBinaryBindingSetSHA256 [32]byte
	pinnedCallsiteEvidenceSHA256 [32]byte
	imageSHA256                  [32]byte
}

type verifiedL8ProfileCorrelation struct {
	descriptorFingerprint [32]byte
	evidenceFingerprint   [32]byte
	policyAuthority       verifiedL8PolicyAuthorityBindings
}

type verifiedL8LeaseCorrelation struct {
	sourceDescriptorFingerprint   [32]byte
	preparedDescriptorFingerprint [32]byte
	hasPreparedDescriptor         bool
	evidenceFingerprint           [32]byte
	policyAuthority               verifiedL8PolicyAuthorityBindings
}

// VerifiedL8Profile is an opaque resolver-owned proof that one normalized
// launch descriptor came from the complete L8 verification boundary.
type VerifiedL8Profile struct {
	seal        verifiedL8ProfileSeal
	correlation verifiedL8ProfileCorrelation
}

type verifiedL8AssetLeaseState struct {
	mu sync.Mutex

	rootDir            string
	root               *os.File
	files              map[string]l8PinnedAsset
	sourceDescriptor   assets.LaunchDescriptor
	material           L8LaunchMaterialWriter
	materialDescriptor assets.LaunchDescriptor
	closed             bool
	cleanupErr         error
}

// VerifiedL8AssetLease retains the verified L8 bundle and any materialized
// launch assets. Its fields are deliberately private and non-serializable.
type VerifiedL8AssetLease struct {
	state       *verifiedL8AssetLeaseState
	correlation verifiedL8LeaseCorrelation
}

// L8LaunchMaterialWriter is the sole transfer boundary for private L8 launch
// material prepared from the pinned verified source bundle.
type L8LaunchMaterialWriter interface {
	WriteAsset(assets.AssetRole, io.Reader) (string, error)
	Validate() error
	Close() error
}

// L8Profile returns the opaque profile only for a successfully sealed L8
// distribution.
func (distribution VerifiedDistribution) L8Profile() (VerifiedL8Profile, bool) {
	if !distribution.l8Profile.seal.active {
		return VerifiedL8Profile{}, false
	}
	return distribution.l8Profile, true
}

// VerifiedL8ProfileMatches verifies the resolver seal and the exact normalized
// descriptor binding without exposing either private fingerprint.
func VerifiedL8ProfileMatches(profile *VerifiedL8Profile, descriptor *assets.LaunchDescriptor) bool {
	if profile == nil || !profile.seal.active || descriptor == nil {
		return false
	}
	result := assets.ValidateAndNormalizeLaunchDescriptor(*descriptor)
	if !result.Valid || result.Normalized == nil {
		return false
	}
	fingerprint, err := buildL8DescriptorFingerprint(*result.Normalized)
	return err == nil && subtle.ConstantTimeCompare(fingerprint[:], profile.correlation.descriptorFingerprint[:]) == 1
}

// VerifiedL8ProfileMatchesLease checks the full private issuance correlation
// while holding the lease lifecycle mutex.
func VerifiedL8ProfileMatchesLease(profile *VerifiedL8Profile, lease *VerifiedL8AssetLease) bool {
	if profile == nil || !profile.seal.active || lease == nil || lease.state == nil {
		return false
	}
	lease.state.mu.Lock()
	defer lease.state.mu.Unlock()

	descriptorMatches := subtle.ConstantTimeCompare(profile.correlation.descriptorFingerprint[:], lease.correlation.sourceDescriptorFingerprint[:])
	if lease.correlation.hasPreparedDescriptor {
		descriptorMatches |= subtle.ConstantTimeCompare(profile.correlation.descriptorFingerprint[:], lease.correlation.preparedDescriptorFingerprint[:])
	}
	matches := descriptorMatches
	matches &= subtle.ConstantTimeCompare(profile.correlation.evidenceFingerprint[:], lease.correlation.evidenceFingerprint[:])
	matches &= subtle.ConstantTimeCompare(profile.correlation.policyAuthority.policyArtifactSHA256[:], lease.correlation.policyAuthority.policyArtifactSHA256[:])
	matches &= subtle.ConstantTimeCompare(profile.correlation.policyAuthority.policySourceLockSHA256[:], lease.correlation.policyAuthority.policySourceLockSHA256[:])
	matches &= subtle.ConstantTimeCompare(profile.correlation.policyAuthority.policyBinaryBindingSetSHA256[:], lease.correlation.policyAuthority.policyBinaryBindingSetSHA256[:])
	matches &= subtle.ConstantTimeCompare(profile.correlation.policyAuthority.pinnedCallsiteEvidenceSHA256[:], lease.correlation.policyAuthority.pinnedCallsiteEvidenceSHA256[:])
	matches &= subtle.ConstantTimeCompare(profile.correlation.policyAuthority.imageSHA256[:], lease.correlation.policyAuthority.imageSHA256[:])
	return matches == 1
}

func buildL8DescriptorFingerprint(descriptor assets.LaunchDescriptor) ([32]byte, error) {
	if descriptor.ID != "l8-production-credentials-image" || len(descriptor.Labels) != 4 ||
		descriptor.Labels[0] != "firecracker" || descriptor.Labels[1] != "reproducible" ||
		descriptor.Labels[2] != "network-profile" || descriptor.Labels[3] != "production-credentials-profile" ||
		len(descriptor.Assets) != 2 || descriptor.Assets[0].Role != assets.AssetRoleKernel ||
		descriptor.Assets[1].Role != assets.AssetRoleRootfs {
		return [32]byte{}, newResolverError(ErrorCodeInvalidRequest, "l8Profile", "", "verified L8 launch descriptor is invalid", ErrInvalidRequest)
	}
	var preimage bytes.Buffer
	l8WriteToken(&preimage, "hal/l8/image-profile/descriptor/v1")
	l8WriteToken(&preimage, string(descriptor.ID))
	l8WriteUint16(&preimage, uint16(len(descriptor.Labels)))
	for _, label := range descriptor.Labels {
		l8WriteToken(&preimage, string(label))
	}
	l8WriteUint16(&preimage, uint16(len(descriptor.Assets)))
	for _, asset := range descriptor.Assets {
		if asset.Source.HostPath == nil || asset.InitConfig != nil || asset.AgentConfig != nil || len(asset.Resources) != 0 || asset.Lock.SizeBytes <= 0 || asset.Lock.LockedAtUnixMillis < 0 {
			return [32]byte{}, newResolverError(ErrorCodeInvalidRequest, "l8Profile", "", "verified L8 launch descriptor is invalid", ErrInvalidRequest)
		}
		digest, err := hex.DecodeString(asset.Lock.Digest.Value)
		if err != nil || len(digest) != sha256.Size {
			return [32]byte{}, newResolverError(ErrorCodeInvalidRequest, "l8Profile", "", "verified L8 launch descriptor is invalid", ErrInvalidRequest)
		}
		l8WriteToken(&preimage, string(asset.ID))
		l8WriteToken(&preimage, string(asset.Role))
		l8WriteToken(&preimage, string(asset.Kind))
		l8WriteUint16(&preimage, uint16(len(asset.Labels)))
		for _, label := range asset.Labels {
			l8WriteToken(&preimage, string(label))
		}
		l8WriteToken(&preimage, string(asset.Source.Type))
		l8WriteToken(&preimage, string(asset.Source.HostPath.Role))
		l8WriteToken(&preimage, asset.Source.HostPath.Path)
		l8WriteToken(&preimage, string(asset.Lock.Digest.Algorithm))
		preimage.Write(digest)
		l8WriteUint64(&preimage, uint64(asset.Lock.SizeBytes))
		l8WriteUint64(&preimage, uint64(asset.Lock.LockedAtUnixMillis))
	}
	return sha256.Sum256(preimage.Bytes()), nil
}

func l8WriteToken(destination *bytes.Buffer, value string) {
	l8WriteUint16(destination, uint16(len(value)))
	destination.WriteString(value)
}

func l8WriteUint16(destination *bytes.Buffer, value uint16) {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	destination.Write(encoded[:])
}

func l8WriteUint64(destination *bytes.Buffer, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	destination.Write(encoded[:])
}

func sealVerifiedL8Profile(descriptorFingerprint [32]byte, evidenceFingerprint [32]byte, imageSHA256 [32]byte, policyComposition l8VerifiedPolicyCompositionDigests) (VerifiedL8Profile, error) {
	return VerifiedL8Profile{seal: verifiedL8ProfileSeal{active: true}, correlation: verifiedL8ProfileCorrelation{descriptorFingerprint: descriptorFingerprint, evidenceFingerprint: evidenceFingerprint, policyAuthority: verifiedL8PolicyAuthorityBindings{policyArtifactSHA256: policyComposition.policyArtifactSHA256, policySourceLockSHA256: policyComposition.policySourceLockSHA256, policyBinaryBindingSetSHA256: policyComposition.policyBinaryBindingSetSHA256, pinnedCallsiteEvidenceSHA256: policyComposition.pinnedCallsiteEvidenceSHA256, imageSHA256: imageSHA256}}}, nil
}

func sealVerifiedL8Distribution(profile VerifiedL8Profile, evidenceFingerprint [32]byte, policyComposition l8VerifiedPolicyCompositionDigests, manifest assetbuild.DistributionManifest, provenance assetbuild.Provenance, descriptor assets.LaunchDescriptor, rootDir string) VerifiedDistribution {
	return VerifiedDistribution{Manifest: manifest, Provenance: provenance, Descriptor: descriptor, l8Profile: profile, l8EvidenceFingerprint: evidenceFingerprint, l8PolicyComposition: policyComposition, rootDir: rootDir}
}
