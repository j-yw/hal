package v2control

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

const guestCredentialIdentityDomain = "hal/l8/guest-credential-identity/v1"

// GuestCredentialSessionIdentity binds one validated child job identity to
// its authenticated session ID. It is intentionally opaque and non-JSON.
type GuestCredentialSessionIdentity struct {
	state *guestCredentialSessionIdentityState
}

type guestCredentialSessionIdentityState struct {
	sessionID   [32]byte
	jobIdentity JobIdentity
}

// NewGuestCredentialSessionIdentity validates and defensively constructs a
// session-bound identity.
func NewGuestCredentialSessionIdentity(sessionID [32]byte, jobIdentity JobIdentity) (GuestCredentialSessionIdentity, error) {
	if err := ValidateJobIdentity(jobIdentity); err != nil {
		return GuestCredentialSessionIdentity{}, err
	}
	if jobIdentity.GuestSessionGeneration != generationForSessionID(sessionID) {
		return GuestCredentialSessionIdentity{}, ErrSessionIdentityMismatch
	}
	return GuestCredentialSessionIdentity{
		state: &guestCredentialSessionIdentityState{
			sessionID:   sessionID,
			jobIdentity: cloneJobIdentity(jobIdentity),
		},
	}, nil
}

// GuestCredentialSessionIdentityFromRoot validates and defensively projects a
// root identity into one session-bound child identity.
func GuestCredentialSessionIdentityFromRoot(sessionID [32]byte, root sandboxruntime.JobCredentialIdentity) (GuestCredentialSessionIdentity, error) {
	jobIdentity, err := JobIdentityFromRoot(root)
	if err != nil {
		return GuestCredentialSessionIdentity{}, err
	}
	return NewGuestCredentialSessionIdentity(sessionID, jobIdentity)
}

// ValidateGuestCredentialSessionIdentity validates both the child identity
// and its exact base64url session-generation correlation.
func ValidateGuestCredentialSessionIdentity(identity GuestCredentialSessionIdentity) error {
	if identity.state == nil {
		return ErrInvalidJobIdentity
	}
	if err := ValidateJobIdentity(identity.state.jobIdentity); err != nil {
		return err
	}
	if identity.state.jobIdentity.GuestSessionGeneration != generationForSessionID(identity.state.sessionID) {
		return ErrSessionIdentityMismatch
	}
	return nil
}

// SessionID returns the fixed-size session ID by value.
func (identity GuestCredentialSessionIdentity) SessionID() [32]byte {
	if identity.state == nil {
		return [32]byte{}
	}
	return identity.state.sessionID
}

// JobIdentity returns a defensive child identity value.
func (identity GuestCredentialSessionIdentity) JobIdentity() JobIdentity {
	if identity.state == nil {
		return JobIdentity{}
	}
	return cloneJobIdentity(identity.state.jobIdentity)
}

// GuestCredentialSessionIdentityDigest returns the frozen session-bound
// domain-separated digest.
func GuestCredentialSessionIdentityDigest(identity GuestCredentialSessionIdentity) ([32]byte, error) {
	if err := ValidateGuestCredentialSessionIdentity(identity); err != nil {
		return [32]byte{}, err
	}
	jobDigest, err := JobIdentityDigest(identity.state.jobIdentity)
	if err != nil {
		return [32]byte{}, err
	}
	hash := sha256.New()
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(guestCredentialIdentityDomain)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write([]byte(guestCredentialIdentityDomain))
	_, _ = hash.Write(identity.state.sessionID[:])
	_, _ = hash.Write(jobDigest[:])
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}
