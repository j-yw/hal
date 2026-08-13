package credentialprotocol

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const helperBootstrapDigestDomain = "hal/l8/guest-helper/bootstrap/v1"

var ErrHelperBootstrapCanonicalDigest = errors.New("credential protocol helper bootstrap canonical digest input is invalid")

// ComputeCanonicalHelperBootstrapSHA256 hashes an already-validated canonical
// bootstrap body with its exact canonical HL8P header. It neither decodes nor
// retains canonicalBody.
func ComputeCanonicalHelperBootstrapSHA256(header HelperPacketHeader, canonicalBody []byte) ([32]byte, error) {
	var digest [32]byte
	if header.Type != PacketTypeBootstrap || header.Sequence != 0 {
		return digest, ErrHelperBootstrapCanonicalDigest
	}
	if err := ValidateHelperPacketHeaderSemantics(header); err != nil {
		return digest, ErrHelperBootstrapCanonicalDigest
	}
	if header.BodyLength == 0 || header.BodyLength > MaxHelperPacketBodyBytes || uint64(header.BodyLength) != uint64(len(canonicalBody)) {
		return digest, ErrHelperBootstrapCanonicalDigest
	}
	canonicalHeader, err := EncodeHelperPacketHeader(header)
	if err != nil {
		return digest, ErrHelperBootstrapCanonicalDigest
	}

	hash := sha256.New()
	var domainLength [2]byte
	binary.BigEndian.PutUint16(domainLength[:], uint16(len(helperBootstrapDigestDomain)))
	_, _ = hash.Write(domainLength[:])
	_, _ = hash.Write([]byte(helperBootstrapDigestDomain))
	_, _ = hash.Write(canonicalHeader[:])
	_, _ = hash.Write(canonicalBody)
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}
