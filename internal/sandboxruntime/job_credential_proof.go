package sandboxruntime

import (
	"crypto/sha256"
	"encoding/binary"
	"time"
)

const (
	jobCredentialActiveProofKind  = "active"
	jobCredentialCleanupProofKind = "cleanup"
	jobCredentialActiveTokenKind  = byte(1)
	jobCredentialCleanupTokenKind = byte(2)
	jobCredentialProofTokenSize   = 96
	jobCredentialIdentityOffset   = 1
	jobCredentialProofIDOffset    = 33
	jobCredentialRevisionOffset   = 65
	jobCredentialFirstTimeOffset  = 73
	jobCredentialSecondTimeOffset = 81
	jobCredentialFlagsOffset      = 89
)

type JobCredentialActiveProofInput struct {
	ProofID   string
	Identity  JobCredentialIdentity
	Revision  uint64
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// JobCredentialActiveProof is a sealed fixed-size correlation token. The
// token contains only digests and numeric correlation data, so fmt's special
// %p handling cannot traverse identity or proof identifiers.
type JobCredentialActiveProof struct {
	token [jobCredentialProofTokenSize]byte
}

func NewJobCredentialActiveProof(input JobCredentialActiveProofInput) (JobCredentialActiveProof, error) {
	if !validJobCredentialSafeID(input.ProofID) || !validJobCredentialIdentity(input.Identity) || input.Revision == 0 ||
		input.IssuedAt.IsZero() || input.ExpiresAt.IsZero() || !input.ExpiresAt.After(input.IssuedAt) ||
		input.IssuedAt.Before(input.Identity.IssuedAt) || input.ExpiresAt.Sub(input.IssuedAt) > MaxJobCredentialLifetime {
		return JobCredentialActiveProof{}, ErrJobCredentialProofInvalid
	}
	var proof JobCredentialActiveProof
	proof.token[0] = jobCredentialActiveTokenKind
	identityDigest := jobCredentialIdentityDigest(input.Identity)
	copy(proof.token[jobCredentialIdentityOffset:jobCredentialProofIDOffset], identityDigest[:])
	proofID := sha256.Sum256([]byte(input.ProofID))
	copy(proof.token[jobCredentialProofIDOffset:jobCredentialRevisionOffset], proofID[:])
	binary.BigEndian.PutUint64(proof.token[jobCredentialRevisionOffset:jobCredentialFirstTimeOffset], input.Revision)
	binary.BigEndian.PutUint64(proof.token[jobCredentialFirstTimeOffset:jobCredentialSecondTimeOffset], uint64(input.IssuedAt.UnixNano()))
	binary.BigEndian.PutUint64(proof.token[jobCredentialSecondTimeOffset:jobCredentialFlagsOffset], uint64(input.ExpiresAt.UnixNano()))
	return proof, nil
}

func ValidateJobCredentialActiveProof(proof JobCredentialActiveProof, identity JobCredentialIdentity, revision uint64, observedAt time.Time) error {
	if !validJobCredentialActiveProof(proof) || !validJobCredentialIdentity(identity) || observedAt.IsZero() {
		return ErrJobCredentialProofInvalid
	}
	if proof.identityDigest() != jobCredentialIdentityDigest(identity) {
		return ErrJobCredentialIdentityMismatch
	}
	if proof.revision() != revision {
		return ErrJobCredentialRevisionStale
	}
	issuedAt, expiresAt := proof.times()
	if observedAt.Before(issuedAt) {
		return ErrJobCredentialProofInvalid
	}
	if !observedAt.Before(expiresAt) {
		return ErrJobCredentialExpired
	}
	return nil
}

func validJobCredentialActiveProof(proof JobCredentialActiveProof) bool {
	if proof.token[0] != jobCredentialActiveTokenKind || proof.revision() == 0 {
		return false
	}
	issuedAt, expiresAt := proof.times()
	return !issuedAt.IsZero() && !expiresAt.IsZero() && expiresAt.After(issuedAt) && expiresAt.Sub(issuedAt) <= MaxJobCredentialLifetime
}

func (proof JobCredentialActiveProof) identityDigest() [sha256.Size]byte {
	var digest [sha256.Size]byte
	copy(digest[:], proof.token[jobCredentialIdentityOffset:jobCredentialProofIDOffset])
	return digest
}

func (proof JobCredentialActiveProof) revision() uint64 {
	return binary.BigEndian.Uint64(proof.token[jobCredentialRevisionOffset:jobCredentialFirstTimeOffset])
}

func (proof JobCredentialActiveProof) times() (time.Time, time.Time) {
	issuedAt := time.Unix(0, int64(binary.BigEndian.Uint64(proof.token[jobCredentialFirstTimeOffset:jobCredentialSecondTimeOffset]))).UTC()
	expiresAt := time.Unix(0, int64(binary.BigEndian.Uint64(proof.token[jobCredentialSecondTimeOffset:jobCredentialFlagsOffset]))).UTC()
	return issuedAt, expiresAt
}

func ActiveProofKind(proof JobCredentialActiveProof) string {
	if !validJobCredentialActiveProof(proof) {
		return ""
	}
	return jobCredentialActiveProofKind
}

type JobCredentialCleanupProofInput struct {
	ProofID            string
	Identity           JobCredentialIdentity
	Revision           uint64
	RevokedAt          time.Time
	AbsenceInspectedAt time.Time
	AuthorityAbsent    bool
	ResourcesAbsent    bool
}

type JobCredentialCleanupProof struct {
	token [jobCredentialProofTokenSize]byte
}

func NewJobCredentialCleanupProof(input JobCredentialCleanupProofInput) (JobCredentialCleanupProof, error) {
	if !validJobCredentialSafeID(input.ProofID) || !validJobCredentialIdentity(input.Identity) || input.Revision == 0 ||
		input.RevokedAt.IsZero() || input.AbsenceInspectedAt.IsZero() || input.AbsenceInspectedAt.Before(input.RevokedAt) ||
		input.RevokedAt.Before(input.Identity.IssuedAt) || !input.AuthorityAbsent || !input.ResourcesAbsent {
		return JobCredentialCleanupProof{}, ErrJobCredentialProofInvalid
	}
	var proof JobCredentialCleanupProof
	proof.token[0] = jobCredentialCleanupTokenKind
	identityDigest := jobCredentialIdentityDigest(input.Identity)
	copy(proof.token[jobCredentialIdentityOffset:jobCredentialProofIDOffset], identityDigest[:])
	proofID := sha256.Sum256([]byte(input.ProofID))
	copy(proof.token[jobCredentialProofIDOffset:jobCredentialRevisionOffset], proofID[:])
	binary.BigEndian.PutUint64(proof.token[jobCredentialRevisionOffset:jobCredentialFirstTimeOffset], input.Revision)
	binary.BigEndian.PutUint64(proof.token[jobCredentialFirstTimeOffset:jobCredentialSecondTimeOffset], uint64(input.RevokedAt.UnixNano()))
	binary.BigEndian.PutUint64(proof.token[jobCredentialSecondTimeOffset:jobCredentialFlagsOffset], uint64(input.AbsenceInspectedAt.UnixNano()))
	proof.token[jobCredentialFlagsOffset] = 3
	return proof, nil
}

func ValidateJobCredentialCleanupProof(proof JobCredentialCleanupProof, identity JobCredentialIdentity, revision uint64, observedAt time.Time) error {
	if !validJobCredentialCleanupProof(proof) || !validJobCredentialIdentity(identity) || observedAt.IsZero() {
		return ErrJobCredentialProofInvalid
	}
	if proof.identityDigest() != jobCredentialIdentityDigest(identity) {
		return ErrJobCredentialIdentityMismatch
	}
	if proof.revision() != revision {
		return ErrJobCredentialRevisionStale
	}
	_, inspectedAt := proof.times()
	if observedAt.Before(inspectedAt) {
		return ErrJobCredentialProofInvalid
	}
	if observedAt.Sub(inspectedAt) > MaxJobCredentialCleanupObservationAge {
		return ErrJobCredentialProofStale
	}
	return nil
}

func validJobCredentialCleanupProof(proof JobCredentialCleanupProof) bool {
	if proof.token[0] != jobCredentialCleanupTokenKind || proof.revision() == 0 || proof.token[jobCredentialFlagsOffset] != 3 {
		return false
	}
	revokedAt, inspectedAt := proof.times()
	return !revokedAt.IsZero() && !inspectedAt.IsZero() && !inspectedAt.Before(revokedAt)
}

func (proof JobCredentialCleanupProof) identityDigest() [sha256.Size]byte {
	var digest [sha256.Size]byte
	copy(digest[:], proof.token[jobCredentialIdentityOffset:jobCredentialProofIDOffset])
	return digest
}

func (proof JobCredentialCleanupProof) revision() uint64 {
	return binary.BigEndian.Uint64(proof.token[jobCredentialRevisionOffset:jobCredentialFirstTimeOffset])
}

func (proof JobCredentialCleanupProof) times() (time.Time, time.Time) {
	revokedAt := time.Unix(0, int64(binary.BigEndian.Uint64(proof.token[jobCredentialFirstTimeOffset:jobCredentialSecondTimeOffset]))).UTC()
	inspectedAt := time.Unix(0, int64(binary.BigEndian.Uint64(proof.token[jobCredentialSecondTimeOffset:jobCredentialFlagsOffset]))).UTC()
	return revokedAt, inspectedAt
}

func CleanupProofKind(proof JobCredentialCleanupProof) string {
	if !validJobCredentialCleanupProof(proof) {
		return ""
	}
	return jobCredentialCleanupProofKind
}

func sameJobCredentialActiveProof(left, right JobCredentialActiveProof) bool {
	return left.token == right.token && validJobCredentialActiveProof(left)
}

func sameJobCredentialCleanupProof(left, right JobCredentialCleanupProof) bool {
	return left.token == right.token && validJobCredentialCleanupProof(left)
}

func jobCredentialIdentityDigest(identity JobCredentialIdentity) [sha256.Size]byte {
	digest, _ := JobCredentialIdentityDigest(identity)
	return digest
}
