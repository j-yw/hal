package localresolver

import (
	"crypto/sha256"
	"encoding/json"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
)

type verifiedL7ProfileSeal struct{}

var activeVerifiedL7ProfileSeal = &verifiedL7ProfileSeal{}

// VerifiedL7Profile is an opaque in-memory proof that a descriptor came from
// complete L7 bundle verification. Its zero value and external literals are
// invalid, and its private fingerprint binds it to one normalized descriptor.
type VerifiedL7Profile struct {
	seal        *verifiedL7ProfileSeal
	fingerprint [sha256.Size]byte
}

// L7Profile returns an opaque L7 profile only after the manifest, provenance,
// checksum inventory, and launch assets have all passed bundle verification.
func (distribution VerifiedDistribution) L7Profile() (VerifiedL7Profile, bool) {
	if distribution.l7Profile.seal != activeVerifiedL7ProfileSeal {
		return VerifiedL7Profile{}, false
	}
	return distribution.l7Profile, true
}

// VerifiedL7ProfileMatches reports whether profile is a genuine resolver-owned
// proof bound to the exact normalized descriptor supplied to Firecracker.
func VerifiedL7ProfileMatches(profile *VerifiedL7Profile, descriptor *assets.LaunchDescriptor) bool {
	if profile == nil || profile.seal != activeVerifiedL7ProfileSeal || descriptor == nil {
		return false
	}
	result := assets.ValidateAndNormalizeLaunchDescriptor(*descriptor)
	if !result.Valid || result.Normalized == nil {
		return false
	}
	fingerprint, ok := l7DescriptorFingerprint(*result.Normalized)
	return ok && fingerprint == profile.fingerprint
}

func newVerifiedL7Profile(descriptor assets.LaunchDescriptor) VerifiedL7Profile {
	fingerprint, ok := l7DescriptorFingerprint(descriptor)
	if !ok {
		return VerifiedL7Profile{}
	}
	return VerifiedL7Profile{
		seal:        activeVerifiedL7ProfileSeal,
		fingerprint: fingerprint,
	}
}

func l7DescriptorFingerprint(descriptor assets.LaunchDescriptor) ([sha256.Size]byte, bool) {
	encoded, err := json.Marshal(descriptor)
	if err != nil {
		return [sha256.Size]byte{}, false
	}
	return sha256.Sum256(encoded), true
}
